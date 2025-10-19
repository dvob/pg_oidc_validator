use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use pgrx::guc::*;
use pgrx::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::ffi::CString;
use std::os::raw::{c_char, c_int};
use std::sync::{Arc, OnceLock, RwLock};
use std::time::{Duration, Instant};

::pgrx::pg_module_magic!();

// Constants
const MAX_VALIDATION_SLOTS: usize = 100; // Max concurrent validations
const MAX_TOKEN_SIZE: usize = 8192;      // Max JWT token size
const MAX_ROLE_SIZE: usize = 256;        // Max role name size
const MAX_AUTHN_ID_SIZE: usize = 256;    // Max authenticated ID size
const MAX_ERROR_SIZE: usize = 512;       // Max error message size
const VALIDATION_TIMEOUT_MS: i64 = 5000; // 5 second timeout

// GUC variable for ISSUER_URL
static ISSUER_URL: GucSetting<Option<CString>> = GucSetting::<Option<CString>>::new(None);

// Global token validator instance (used by background worker)
static TOKEN_VALIDATOR: OnceLock<Arc<OidcTokenValidator>> = OnceLock::new();

// Shared memory state pointer (initialized at startup)
static mut SHARED_STATE: *mut SharedValidatorState = std::ptr::null_mut();

// Previous hooks
static mut PREV_SHMEM_STARTUP_HOOK: Option<unsafe extern "C-unwind" fn()> = None;
static mut PREV_SHMEM_REQUEST_HOOK: Option<unsafe extern "C-unwind" fn()> = None;

pub const PG_OAUTH_VALIDATOR_MAGIC: u32 = 0x20250220;

#[repr(C)]
pub struct ValidatorModuleState {
    pub sversion: c_int,
    pub private_data: *mut std::ffi::c_void,
}

#[repr(C)]
pub struct ValidatorModuleResult {
    pub authorized: bool,
    pub authn_id: *mut c_char,
}

pub type ValidatorStartupCB = Option<unsafe extern "C" fn(state: *mut ValidatorModuleState)>;

pub type ValidatorShutdownCB = Option<unsafe extern "C" fn(state: *mut ValidatorModuleState)>;

pub type ValidatorValidateCB = Option<
    unsafe extern "C" fn(
        state: *const ValidatorModuleState,
        token: *const c_char,
        role: *const c_char,
        result: *mut ValidatorModuleResult,
    ) -> bool,
>;

#[repr(C)]
pub struct OAuthValidatorCallbacks {
    /// Must be set to PG_OAUTH_VALIDATOR_MAGIC
    pub magic: u32,
    pub startup_cb: ValidatorStartupCB,
    pub shutdown_cb: ValidatorShutdownCB,
    pub validate_cb: ValidatorValidateCB,
}

// ============================================================================
// Shared Memory Structures for Background Worker Communication
// ============================================================================

/// A single validation slot for one backend's request/response
#[repr(C)]
struct ValidationSlot {
    /// Spinlock protecting this slot
    lock: pg_sys::slock_t,

    /// Slot state
    in_use: bool,
    backend_pid: i32,
    request_time: i64,      // Timestamp when request was made

    /// Backend's latch to wake up when response is ready
    backend_latch: *mut pg_sys::Latch,

    /// Request data
    token: [u8; MAX_TOKEN_SIZE],
    token_len: usize,
    role: [u8; MAX_ROLE_SIZE],
    role_len: usize,

    /// Response data
    response_ready: bool,
    success: bool,
    authorized: bool,
    authn_id: [u8; MAX_AUTHN_ID_SIZE],
    authn_id_len: usize,
    error_msg: [u8; MAX_ERROR_SIZE],
    error_msg_len: usize,
}

/// Shared state for all validation slots
#[repr(C)]
struct SharedValidatorState {
    /// LWLock for allocating slots
    allocation_lock: *mut pg_sys::LWLock,

    /// Array of validation slots
    slots: [ValidationSlot; MAX_VALIDATION_SLOTS],

    /// Work queue: indices of slots with pending requests
    /// Protected by queue_lock
    queue_lock: pg_sys::slock_t,
    pending_queue: [usize; MAX_VALIDATION_SLOTS],
    queue_head: usize,
    queue_tail: usize,

    /// Worker latch: signaled when new work is enqueued
    worker_latch: pg_sys::Latch,

    /// Statistics
    total_validations: pg_sys::pg_atomic_uint64,
    successful_validations: pg_sys::pg_atomic_uint64,
    failed_validations: pg_sys::pg_atomic_uint64,
}

impl ValidationSlot {
    unsafe fn init(&mut self) {
        pg_sys::SpinLockInit(&mut self.lock as *mut _);
        self.in_use = false;
        self.backend_pid = 0;
        self.request_time = 0;
        self.backend_latch = std::ptr::null_mut();
        self.token_len = 0;
        self.role_len = 0;
        self.response_ready = false;
        self.success = false;
        self.authorized = false;
        self.authn_id_len = 0;
        self.error_msg_len = 0;
    }

    /// Try to acquire this slot for the current backend
    unsafe fn try_acquire(&mut self, backend_pid: i32) -> bool {
        pg_sys::SpinLockAcquire(&mut self.lock as *mut _);
        let acquired = if !self.in_use {
            self.in_use = true;
            self.backend_pid = backend_pid;
            self.request_time = current_timestamp_ms();
            self.response_ready = false;
            true
        } else {
            false
        };
        pg_sys::SpinLockRelease(&mut self.lock as *mut _);
        acquired
    }

    /// Release this slot
    unsafe fn release(&mut self) {
        pg_sys::SpinLockAcquire(&mut self.lock as *mut _);
        self.in_use = false;
        self.backend_pid = 0;
        pg_sys::SpinLockRelease(&mut self.lock as *mut _);
    }

    /// Check if response is ready (called with lock NOT held)
    unsafe fn is_response_ready(&mut self) -> bool {
        pg_sys::SpinLockAcquire(&mut self.lock as *mut _);
        let ready = self.response_ready;
        pg_sys::SpinLockRelease(&mut self.lock as *mut _);
        ready
    }

    /// Set the request data (token and role)
    unsafe fn set_request(&mut self, token: &str, role: &str) -> Result<(), String> {
        let token_bytes = token.as_bytes();
        let role_bytes = role.as_bytes();

        if token_bytes.len() > MAX_TOKEN_SIZE {
            return Err(format!("Token too large: {} bytes", token_bytes.len()));
        }
        if role_bytes.len() > MAX_ROLE_SIZE {
            return Err(format!("Role too large: {} bytes", role_bytes.len()));
        }

        pg_sys::SpinLockAcquire(&mut self.lock as *mut _);
        self.token[..token_bytes.len()].copy_from_slice(token_bytes);
        self.token_len = token_bytes.len();
        self.role[..role_bytes.len()].copy_from_slice(role_bytes);
        self.role_len = role_bytes.len();
        pg_sys::SpinLockRelease(&mut self.lock as *mut _);

        Ok(())
    }

    /// Get the response data (called after response_ready is true)
    unsafe fn get_response(&mut self) -> (bool, bool, String, String) {
        pg_sys::SpinLockAcquire(&mut self.lock as *mut _);
        let success = self.success;
        let authorized = self.authorized;
        let authn_id = String::from_utf8_lossy(&self.authn_id[..self.authn_id_len]).to_string();
        let error_msg = String::from_utf8_lossy(&self.error_msg[..self.error_msg_len]).to_string();
        pg_sys::SpinLockRelease(&mut self.lock as *mut _);

        (success, authorized, authn_id, error_msg)
    }

    /// Worker: get request data
    unsafe fn get_request(&mut self) -> Option<(String, String)> {
        pg_sys::SpinLockAcquire(&mut self.lock as *mut _);
        if !self.in_use || self.response_ready {
            pg_sys::SpinLockRelease(&mut self.lock as *mut _);
            return None;
        }

        let token = String::from_utf8_lossy(&self.token[..self.token_len]).to_string();
        let role = String::from_utf8_lossy(&self.role[..self.role_len]).to_string();
        pg_sys::SpinLockRelease(&mut self.lock as *mut _);

        Some((token, role))
    }

    /// Worker: set response data
    unsafe fn set_response(
        &mut self,
        success: bool,
        authorized: bool,
        authn_id: &str,
        error_msg: &str,
    ) -> Result<(), String> {
        let authn_id_bytes = authn_id.as_bytes();
        let error_msg_bytes = error_msg.as_bytes();

        if authn_id_bytes.len() > MAX_AUTHN_ID_SIZE {
            return Err(format!("Authn ID too large: {} bytes", authn_id_bytes.len()));
        }
        if error_msg_bytes.len() > MAX_ERROR_SIZE {
            return Err(format!("Error message too large: {} bytes", error_msg_bytes.len()));
        }

        pg_sys::SpinLockAcquire(&mut self.lock as *mut _);
        self.success = success;
        self.authorized = authorized;
        self.authn_id[..authn_id_bytes.len()].copy_from_slice(authn_id_bytes);
        self.authn_id_len = authn_id_bytes.len();
        self.error_msg[..error_msg_bytes.len()].copy_from_slice(error_msg_bytes);
        self.error_msg_len = error_msg_bytes.len();
        self.response_ready = true;
        pg_sys::SpinLockRelease(&mut self.lock as *mut _);

        Ok(())
    }
}

/// Get current timestamp in milliseconds (for timeout tracking)
fn current_timestamp_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}

// ============================================================================
// Work Queue Management
// ============================================================================

/// Enqueue a slot index for the worker to process
unsafe fn enqueue_work(state: *mut SharedValidatorState, slot_idx: usize) {
    pg_sys::SpinLockAcquire(&mut (*state).queue_lock as *mut _);

    // Check if queue is full (should never happen with same number of slots and queue entries)
    let next_tail = ((*state).queue_tail + 1) % MAX_VALIDATION_SLOTS;
    if next_tail != (*state).queue_head {
        (*state).pending_queue[(*state).queue_tail] = slot_idx;
        (*state).queue_tail = next_tail;
    }

    pg_sys::SpinLockRelease(&mut (*state).queue_lock as *mut _);

    // Wake up the worker
    pg_sys::SetLatch(&mut (*state).worker_latch as *mut _);
}

/// Dequeue a slot index for processing (returns None if queue is empty)
unsafe fn dequeue_work(state: *mut SharedValidatorState) -> Option<usize> {
    pg_sys::SpinLockAcquire(&mut (*state).queue_lock as *mut _);

    let result = if (*state).queue_head == (*state).queue_tail {
        // Queue is empty
        None
    } else {
        let slot_idx = (*state).pending_queue[(*state).queue_head];
        (*state).queue_head = ((*state).queue_head + 1) % MAX_VALIDATION_SLOTS;
        Some(slot_idx)
    };

    pg_sys::SpinLockRelease(&mut (*state).queue_lock as *mut _);
    result
}

// ============================================================================
// Shared Memory Management
// ============================================================================

/// Initialize shared memory state (called from shmem_startup_hook)
unsafe fn init_shared_state() {
    let state = pg_sys::ShmemInitStruct(
        c"pg_oidc_validator_state".as_ptr() as *const i8,
        std::mem::size_of::<SharedValidatorState>(),
        &mut false as *mut bool,
    ) as *mut SharedValidatorState;

    if state.is_null() {
        panic!("Failed to allocate shared memory for pg_oidc_validator");
    }

    // Initialize the allocation lock
    (*state).allocation_lock = &mut (*pg_sys::GetNamedLWLockTranche(
        c"pg_oidc_validator_locks".as_ptr() as *const i8,
    ))
    .lock as *mut pg_sys::LWLock;

    // Initialize all slots
    for i in 0..MAX_VALIDATION_SLOTS {
        (*state).slots[i].init();
    }

    // Initialize work queue
    pg_sys::SpinLockInit(&mut (*state).queue_lock as *mut _);
    (*state).queue_head = 0;
    (*state).queue_tail = 0;

    // Initialize worker latch (just zero it out, worker will take ownership)
    std::ptr::write_bytes(&mut (*state).worker_latch as *mut _, 0, 1);

    // Initialize statistics
    pg_sys::pg_atomic_init_u64(&mut (*state).total_validations as *mut _, 0);
    pg_sys::pg_atomic_init_u64(&mut (*state).successful_validations as *mut _, 0);
    pg_sys::pg_atomic_init_u64(&mut (*state).failed_validations as *mut _, 0);

    // Store the pointer globally
    SHARED_STATE = state;

    log!("Shared memory initialized for pg_oidc_validator");
}

/// Get a pointer to the shared state
unsafe fn get_shared_state() -> *mut SharedValidatorState {
    if SHARED_STATE.is_null() {
        panic!("Shared state not initialized");
    }
    SHARED_STATE
}

/// Allocate a validation slot for the current backend
unsafe fn allocate_slot() -> Result<*mut ValidationSlot, String> {
    let state = get_shared_state();
    let my_pid = pg_sys::MyProcPid;

    // Use LWLock to serialize slot allocation
    pg_sys::LWLockAcquire((*state).allocation_lock, pg_sys::LWLockMode::LW_EXCLUSIVE);

    let mut slot_ptr: *mut ValidationSlot = std::ptr::null_mut();

    // Find an available slot
    for i in 0..MAX_VALIDATION_SLOTS {
        let slot = &mut (*state).slots[i];
        if slot.try_acquire(my_pid) {
            slot_ptr = slot as *mut ValidationSlot;
            break;
        }
    }

    pg_sys::LWLockRelease((*state).allocation_lock);

    if slot_ptr.is_null() {
        Err("No available validation slots (all busy)".to_string())
    } else {
        Ok(slot_ptr)
    }
}

/// Submit a validation request and wait for response (using latches - efficient!)
unsafe fn validate_via_worker(token: &str, role: &str) -> Result<ValidationResult, String> {
    let state = get_shared_state();

    // Allocate a slot
    let slot = allocate_slot()?;
    let slot_idx = ((slot as usize) - ((*state).slots.as_ptr() as usize)) / std::mem::size_of::<ValidationSlot>();

    // Store our latch so worker can wake us up
    (*slot).backend_latch = &mut (*pg_sys::MyProc).procLatch as *mut _;

    // Set the request data
    (*slot).set_request(token, role)?;

    // Enqueue work for the worker and wake it up
    enqueue_work(state, slot_idx);

    // Wait efficiently using latch - uses ZERO CPU while waiting!
    let timeout_ms = VALIDATION_TIMEOUT_MS;
    // Use WAIT_EVENT_EXTENSION for custom wait events
    let wait_event = 0x0D000000u32; // PG_WAIT_EXTENSION base

    let rc = pg_sys::WaitLatch(
        &mut (*pg_sys::MyProc).procLatch as *mut _,
        (pg_sys::WL_LATCH_SET | pg_sys::WL_TIMEOUT | pg_sys::WL_EXIT_ON_PM_DEATH) as i32,
        timeout_ms,
        wait_event,
    );

    // Reset the latch for future use
    pg_sys::ResetLatch(&mut (*pg_sys::MyProc).procLatch as *mut _);

    // Check if we have a response
    if (*slot).is_response_ready() {
        let (success, authorized, authn_id, error_msg) = (*slot).get_response();

        // Release the slot
        (*slot).release();

        if success {
            return Ok(ValidationResult {
                authenticated_id: authn_id,
                authorized,
            });
        } else {
            return Err(error_msg);
        }
    } else {
        // Timeout or postmaster death
        (*slot).release();

        if rc & pg_sys::WL_TIMEOUT as i32 != 0 {
            return Err(format!("Validation timeout after {} ms", timeout_ms));
        } else {
            return Err("Validation interrupted (postmaster died?)".to_string());
        }
    }
}

// ============================================================================
// OIDC Discovery and JWT structures
// ============================================================================

#[derive(Debug, Deserialize)]
struct OidcDiscovery {
    jwks_uri: String,
}

#[derive(Debug, Deserialize)]
struct Jwks {
    keys: Vec<JwkKey>,
}

#[derive(Debug, Deserialize, Clone)]
struct JwkKey {
    kid: Option<String>,
    kty: String,
    #[serde(rename = "use")]
    _key_use: Option<String>,
    _alg: Option<String>,
    n: Option<String>,
    e: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Claims {
    sub: String,
    preferred_username: Option<String>,
    #[serde(flatten)]
    extra: HashMap<String, serde_json::Value>,
}

// ============================================================================
// Token Validator Abstraction
// ============================================================================

/// Result of token validation
#[derive(Debug)]
pub struct ValidationResult {
    pub authenticated_id: String,
    pub authorized: bool,
}

/// Trait for token validators
pub trait TokenValidator: Send + Sync {
    /// Validate a token and return the authenticated identity
    fn validate(
        &self,
        token: &str,
        role: &str,
    ) -> Result<ValidationResult, Box<dyn std::error::Error>>;
}

/// Provides the issuer URL from GUC configuration
fn get_issuer_url() -> Result<String, Box<dyn std::error::Error>> {
    let issuer_cstring = ISSUER_URL
        .get()
        .ok_or("pg_oidc_validator.issuer_url is not configured")?;

    Ok(issuer_cstring.to_str()?.to_string())
}

// ============================================================================
// JWKS Cache with Rate-Limited Refresh
// ============================================================================

struct JwksCache {
    keys: RwLock<HashMap<String, DecodingKey>>,
    last_refresh: RwLock<Option<Instant>>,
    refresh_cooldown: Duration,
}

impl JwksCache {
    fn new(refresh_cooldown: Duration) -> Self {
        Self {
            keys: RwLock::new(HashMap::new()),
            last_refresh: RwLock::new(None),
            refresh_cooldown,
        }
    }

    /// Initialize cache with JWKS keys from the issuer
    fn initialize(&self, issuer_url: &str) -> Result<usize, Box<dyn std::error::Error>> {
        let keys = Self::fetch_jwks(issuer_url)?;
        let count = keys.len();

        *self.keys.write().unwrap() = keys;
        *self.last_refresh.write().unwrap() = Some(Instant::now());

        Ok(count)
    }

    /// Get a key by kid, potentially triggering a refresh if missing
    fn get_key(
        &self,
        kid: &str,
        issuer_url: &str,
    ) -> Result<DecodingKey, Box<dyn std::error::Error>> {
        // First, try to get the key from cache
        {
            let keys = self.keys.read().unwrap();
            if let Some(key) = keys.get(kid) {
                return Ok(key.clone());
            }
        }

        // Key not found - check if we can refresh
        let can_refresh = {
            let last_refresh = self.last_refresh.read().unwrap();
            match *last_refresh {
                None => true, // Never refreshed
                Some(last) => last.elapsed() >= self.refresh_cooldown,
            }
        };

        if can_refresh {
            // Refresh the cache
            log!("Fetching JWKS keys for key ID '{}'", kid);
            let new_keys = Self::fetch_jwks(issuer_url)?;
            let key_count = new_keys.len();

            let mut keys = self.keys.write().unwrap();
            *keys = new_keys;
            *self.last_refresh.write().unwrap() = Some(Instant::now());

            log!(
                "JWKS cache populated with {} keys (backend PID: {})",
                key_count,
                std::process::id()
            );

            // Try again
            if let Some(key) = keys.get(kid) {
                return Ok(key.clone());
            }
        } else {
            return Err(format!("Unknown key ID '{}' (refresh on cooldown)", kid).into());
        }
        Err(format!("Unknown key ID '{}' after refresh", kid).into())
    }

    /// Fetch JWKS keys from the issuer
    fn fetch_jwks(
        issuer_url: &str,
    ) -> Result<HashMap<String, DecodingKey>, Box<dyn std::error::Error>> {
        let discovery_url = format!(
            "{}/.well-known/openid-configuration",
            issuer_url.trim_end_matches('/')
        );

        log!("Fetching OIDC discovery from {}", discovery_url);
        let discovery: OidcDiscovery = reqwest::blocking::get(&discovery_url)?.json()?;

        log!("Fetching JWKS from {}", discovery.jwks_uri);
        let jwks: Jwks = reqwest::blocking::get(&discovery.jwks_uri)?.json()?;

        let mut keys = HashMap::new();
        for key in jwks.keys {
            if key.kty == "RSA" {
                if let (Some(n), Some(e), Some(kid)) = (key.n, key.e, key.kid) {
                    if let Ok(decoding_key) = DecodingKey::from_rsa_components(&n, &e) {
                        keys.insert(kid, decoding_key);
                    }
                }
            }
        }

        Ok(keys)
    }
}

// ============================================================================
// OIDC Token Validator Implementation
// ============================================================================

pub struct OidcTokenValidator {
    cache: JwksCache,
}

impl OidcTokenValidator {
    /// Create a new OIDC token validator
    pub fn new(refresh_cooldown: Duration) -> Self {
        Self {
            cache: JwksCache::new(refresh_cooldown),
        }
    }

    /// Initialize the validator by fetching JWKS keys
    pub fn initialize(&self, issuer_url: &str) -> Result<usize, Box<dyn std::error::Error>> {
        self.cache.initialize(issuer_url)
    }
}

impl TokenValidator for OidcTokenValidator {
    fn validate(
        &self,
        token: &str,
        _role: &str,
    ) -> Result<ValidationResult, Box<dyn std::error::Error>> {
        let issuer_url = get_issuer_url()?;

        // Decode header to get key ID
        let header = decode_header(token)?;
        let kid = header.kid.ok_or("Token missing 'kid' in header")?;

        // Get the decoding key (may trigger cache refresh)
        let key = self.cache.get_key(&kid, &issuer_url)?;

        // Set up validation
        let mut validation = Validation::new(Algorithm::RS256);
        validation.validate_aud = false;

        // Decode and validate token
        let token_data = decode::<Claims>(token, &key, &validation)?;

        Ok(ValidationResult {
            authenticated_id: token_data.claims.sub,
            authorized: true,
        })
    }
}

// ============================================================================
// Background Worker Implementation
// ============================================================================

/// Background worker main function
#[no_mangle]
#[pg_guard]
pub extern "C-unwind" fn jwks_validator_worker_main(_arg: pg_sys::Datum) {
    unsafe {
        // Unblock signals (allows shutdown via SIGTERM)
        pg_sys::BackgroundWorkerUnblockSignals();

        log!("JWKS validator background worker started");

        // Get the global validator instance
        let validator = match TOKEN_VALIDATOR.get() {
            Some(v) => v,
            None => {
                warning!("Token validator not initialized in background worker");
                return;
            }
        };

        let state = get_shared_state();

        // Initialize the worker latch (this also claims ownership for this process)
        pg_sys::InitLatch(&mut (*state).worker_latch as *mut _);

        // Main processing loop - efficient, event-driven!
        // This loop uses ZERO CPU when idle
        loop {
            // Process all pending work from the queue
            while let Some(slot_idx) = dequeue_work(state) {
                process_slot(validator, state, slot_idx);
            }

            // No more work - sleep until a backend wakes us up
            // This uses ZERO CPU while waiting!
            let wait_event = 0x0D000000u32; // PG_WAIT_EXTENSION base
            let rc = pg_sys::WaitLatch(
                &mut (*state).worker_latch as *mut _,
                (pg_sys::WL_LATCH_SET | pg_sys::WL_TIMEOUT | pg_sys::WL_EXIT_ON_PM_DEATH) as i32,
                1000, // Wake up every second to check for shutdown
                wait_event,
            );

            // Reset latch for next iteration
            pg_sys::ResetLatch(&mut (*state).worker_latch as *mut _);

            // Check if we should exit (postmaster died)
            if rc & pg_sys::WL_EXIT_ON_PM_DEATH as i32 != 0 {
                log!("JWKS validator background worker shutting down (postmaster died)");
                break;
            }
        }

        log!("JWKS validator background worker exiting");
    }
}

/// Process a single validation request from a slot
unsafe fn process_slot(validator: &Arc<OidcTokenValidator>, state: *mut SharedValidatorState, slot_idx: usize) {
    let slot = &mut (*state).slots[slot_idx];

    // Get the request data
    if let Some((token, role)) = slot.get_request() {
        // Increment total validations
        pg_sys::pg_atomic_fetch_add_u64(&mut (*state).total_validations as *mut _, 1);

        // Perform the validation
        match validator.validate(&token, &role) {
            Ok(validation_result) => {
                // Success - write response
                if let Err(e) = slot.set_response(
                    true,
                    validation_result.authorized,
                    &validation_result.authenticated_id,
                    "",
                ) {
                    log!("Failed to set response: {}", e);
                } else {
                    pg_sys::pg_atomic_fetch_add_u64(
                        &mut (*state).successful_validations as *mut _,
                        1,
                    );
                }
            }
            Err(e) => {
                // Failure - write error response
                let error_msg = e.to_string();
                if let Err(e) = slot.set_response(false, false, "", &error_msg) {
                    log!("Failed to set error response: {}", e);
                } else {
                    pg_sys::pg_atomic_fetch_add_u64(
                        &mut (*state).failed_validations as *mut _,
                        1,
                    );
                }
            }
        }

        // Wake up the waiting backend
        if !slot.backend_latch.is_null() {
            pg_sys::SetLatch(slot.backend_latch);
        }
    }
}

// ============================================================================
// PostgreSQL OAuth Validator Callbacks
// ============================================================================

/// Validator callback implementation
unsafe extern "C" fn validate_cb(
    _state: *const ValidatorModuleState,
    token: *const c_char,
    role: *const c_char,
    result: *mut ValidatorModuleResult,
) -> bool {
    use std::ffi::CStr;

    // Convert C strings to Rust
    let token_str = match CStr::from_ptr(token).to_str() {
        Ok(s) => s,
        Err(e) => {
            eprint!("failed to obtain string '{}'", e);
            (*result).authorized = false;
            (*result).authn_id = std::ptr::null_mut();
            return false;
        }
    };

    let role_str = CStr::from_ptr(role).to_str().unwrap_or("unknown");

    info!("Validating JWT token for role '{}' via background worker", role_str);

    // Validate via background worker using shared memory communication
    match validate_via_worker(token_str, role_str) {
        Ok(validation_result) => {
            info!(
                "Token validated successfully for user '{}'",
                validation_result.authenticated_id
            );

            let username_cstr = match CString::new(validation_result.authenticated_id) {
                Ok(s) => s,
                Err(e) => {
                    log!("Failed to create CString: {}", e);
                    (*result).authorized = false;
                    (*result).authn_id = std::ptr::null_mut();
                    return false;
                }
            };

            let authn_id = pg_sys::pstrdup(username_cstr.as_ptr());

            // Set the result
            (*result).authn_id = authn_id;
            (*result).authorized = validation_result.authorized;
        }
        Err(e) => {
            warning!("Token validation failed: {}", e);
            (*result).authorized = false;
            (*result).authn_id = std::ptr::null_mut();
        }
    }

    true
}

static CALLBACKS: OAuthValidatorCallbacks = OAuthValidatorCallbacks {
    magic: PG_OAUTH_VALIDATOR_MAGIC,
    startup_cb: None,
    shutdown_cb: None,
    validate_cb: Some(validate_cb),
};

// ============================================================================
// Module Initialization
// ============================================================================

/// Shared memory request hook - called early to request shared memory
#[pg_guard]
unsafe extern "C-unwind" fn oidc_validator_shmem_request() {
    // Call previous hook if it exists
    if let Some(prev_hook) = PREV_SHMEM_REQUEST_HOOK {
        prev_hook();
    }

    // Request shared memory
    let shmem_size = std::mem::size_of::<SharedValidatorState>();
    pg_sys::RequestAddinShmemSpace(shmem_size);
    pg_sys::RequestNamedLWLockTranche(c"pg_oidc_validator_locks".as_ptr() as *const i8, 1);
}

/// Shared memory startup hook
#[pg_guard]
unsafe extern "C-unwind" fn oidc_validator_shmem_startup() {
    // Call previous hook if it exists
    if let Some(prev_hook) = PREV_SHMEM_STARTUP_HOOK {
        prev_hook();
    }

    // Initialize our shared memory
    init_shared_state();
}

#[no_mangle]
pub extern "C" fn _PG_init() {
    unsafe {
        // Check if we're being loaded via shared_preload_libraries
        if !pg_sys::process_shared_preload_libraries_in_progress {
            log!(
                "pg_oidc_validator must be loaded via shared_preload_libraries. \
                 Add it to postgresql.conf: shared_preload_libraries = 'pg_oidc_validator'"
            );
            return;
        }
    }

    // Define GUC for issuer URL
    GucRegistry::define_string_guc(
        c"pg_oidc_validator.issuer_url",
        c"OIDC issuer URL for JWT token validation",
        c"The base URL of the OIDC provider (e.g., https://accounts.google.com)",
        &ISSUER_URL,
        GucContext::Postmaster, // Requires restart to change
        GucFlags::default(),
    );

    // Install hooks for shared memory
    unsafe {
        // Install shmem_request_hook (for requesting shared memory)
        PREV_SHMEM_REQUEST_HOOK = pg_sys::shmem_request_hook;
        pg_sys::shmem_request_hook = Some(oidc_validator_shmem_request);

        // Install shmem_startup_hook (for initializing shared memory)
        PREV_SHMEM_STARTUP_HOOK = pg_sys::shmem_startup_hook;
        pg_sys::shmem_startup_hook = Some(oidc_validator_shmem_startup);
    }

    // Create the token validator with 60-second refresh cooldown
    // Cache starts empty - will be populated on first validation attempt
    let validator = Arc::new(OidcTokenValidator::new(Duration::from_secs(60)));
    match get_issuer_url() {
        Ok(url) => match validator.initialize(&url) {
            Ok(count) => log!("successfully initialized JWKS cache with {} keys", count),
            Err(err) => {
                warning!("failed to initialize JWKS cache: {}", err);
            }
        },
        Err(err) => warning!("issuer_url not configured: {}", err),
    };

    // Store the validator globally
    if TOKEN_VALIDATOR.set(validator).is_err() {
        warning!("Failed to set global token validator (already initialized?)");
    }

    // Register background worker
    unsafe {
        let mut worker = std::mem::zeroed::<pg_sys::BackgroundWorker>();

        // Set worker name
        let name = c"JWKS Validator Worker";
        let name_bytes = name.to_bytes_with_nul();
        worker.bgw_name[..name_bytes.len()].copy_from_slice(
            std::slice::from_raw_parts(name_bytes.as_ptr() as *const i8, name_bytes.len())
        );

        // Set worker type
        let worker_type = c"pg_oidc_validator";
        let type_bytes = worker_type.to_bytes_with_nul();
        worker.bgw_type[..type_bytes.len()].copy_from_slice(
            std::slice::from_raw_parts(type_bytes.as_ptr() as *const i8, type_bytes.len())
        );

        // Worker flags (only need shared memory access, no database connection)
        worker.bgw_flags = pg_sys::BGWORKER_SHMEM_ACCESS as i32;
        worker.bgw_start_time = pg_sys::BgWorkerStartTime::BgWorkerStart_PostmasterStart;
        worker.bgw_restart_time = 10; // Restart after 10 seconds if crashed

        // Set library name (must match the actual .so file name)
        let lib_name = c"oidc_validator";
        let lib_bytes = lib_name.to_bytes_with_nul();
        worker.bgw_library_name[..lib_bytes.len()].copy_from_slice(
            std::slice::from_raw_parts(lib_bytes.as_ptr() as *const i8, lib_bytes.len())
        );

        let func_name = c"jwks_validator_worker_main";
        let func_bytes = func_name.to_bytes_with_nul();
        worker.bgw_function_name[..func_bytes.len()].copy_from_slice(
            std::slice::from_raw_parts(func_bytes.as_ptr() as *const i8, func_bytes.len())
        );

        worker.bgw_main_arg = pg_sys::Datum::from(0);
        worker.bgw_notify_pid = 0;

        pg_sys::RegisterBackgroundWorker(&mut worker as *mut _);
    }

    log!("pg_oidc_validator loaded successfully with background worker");
}

#[no_mangle]
pub extern "C" fn _PG_oauth_validator_module_init() -> *const OAuthValidatorCallbacks {
    log!("OAuth validator module init called for new connection");
    &CALLBACKS
}
