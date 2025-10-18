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

// GUC variable for ISSUER_URL
static ISSUER_URL: GucSetting<Option<CString>> = GucSetting::<Option<CString>>::new(None);

// Global token validator instance
static TOKEN_VALIDATOR: OnceLock<Arc<OidcTokenValidator>> = OnceLock::new();

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

// OIDC Discovery and JWT structures
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
            eprint!("faild to obtain string '{}'", e);
            (*result).authorized = false;
            (*result).authn_id = std::ptr::null_mut();
            return false;
        }
    };

    let role_str = CStr::from_ptr(role).to_str().unwrap_or("unknown");

    info!("Validating JWT token for role '{}'", role_str);

    // Get the global validator instance
    let validator = match TOKEN_VALIDATOR.get() {
        Some(v) => v,
        None => {
            warning!("Token validator not initialized");
            (*result).authorized = false;
            (*result).authn_id = std::ptr::null_mut();
            return false;
        }
    };

    // Validate the JWT token
    match validator.validate(token_str, role_str) {
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

#[no_mangle]
pub extern "C" fn _PG_init() {
    unsafe {
        // Check if we're being loaded via shared_preload_libraries
        if !pg_sys::process_shared_preload_libraries_in_progress {
            log!(
                "pg_oidc_validator is not loaded via shared_preload_libraries. \
                 JWKS keys will be fetched for each connection, which may cause performance issues."
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

    // Create the token validator with 60-second refresh cooldown
    // Cache starts empty - will be populated on first validation attempt
    let validator = Arc::new(OidcTokenValidator::new(Duration::from_secs(60)));
    match get_issuer_url() {
        Ok(url) => match validator.initialize(&url) {
            Ok(count) => log!("successfully initialized JWKS cache with {} keys", count),
            Err(err) => {
                warning!("failed to initialize jwks cache: {}", err);
            }
        },
        Err(err) => warning!("failed to obtain url {}", err),
    };

    // Store the validator globally
    if TOKEN_VALIDATOR.set(validator).is_err() {
        warning!("Failed to set global token validator (already initialized?)");
    } else {
        log!("pg_oidc_validator loaded successfully (JWKS will be fetched on first use)");
    }
}

#[no_mangle]
pub extern "C" fn _PG_oauth_validator_module_init() -> *const OAuthValidatorCallbacks {
    log!("OAuth validator module init called for new connection");
    &CALLBACKS
}
