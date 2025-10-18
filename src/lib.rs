use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use pgrx::guc::*;
use pgrx::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::ffi::CString;
use std::os::raw::{c_char, c_int};
use std::sync::OnceLock;

::pgrx::pg_module_magic!();

// GUC variable for ISSUER_URL
static ISSUER_URL: GucSetting<Option<CString>> = GucSetting::<Option<CString>>::new(None);

// Cache for JWKS keys - initialized once in _PG_init()
// OnceLock allows one-time initialization and lock-free concurrent reads
static JWKS_CACHE: OnceLock<HashMap<String, DecodingKey>> = OnceLock::new();

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

fn load_jwks() -> Result<HashMap<String, DecodingKey>, Box<dyn std::error::Error>> {
    // Get ISSUER_URL from GUC setting
    let issuer_cstring = ISSUER_URL
        .get()
        .ok_or("pg_oidc_validator.issuer_url is not configured")?;

    let issuer_url = issuer_cstring.to_str()?;

    let discovery_url = format!(
        "{}/.well-known/openid-configuration",
        issuer_url.trim_end_matches('/')
    );

    log!("obtain public keys");
    let discovery: OidcDiscovery = reqwest::blocking::get(&discovery_url)?.json()?;

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

fn validate_token(token: &str) -> Result<String, Box<dyn std::error::Error>> {
    let header = decode_header(token)?;
    let kid = header.kid.ok_or("Token missing 'kid' in header")?;

    // Read from cache - lock-free after initialization
    let cache = JWKS_CACHE.get().ok_or("JWKS cache not initialized")?;

    let key = cache
        .get(&kid)
        .ok_or_else(|| format!("Unknown key ID: {}", kid))?;

    // Set up validation
    let mut validation = Validation::new(Algorithm::RS256);
    validation.validate_aud = false;

    let token_data = decode::<Claims>(token, key, &validation)?;

    // let user = token_data
    //     .claims
    //     .preferred_username
    //     .ok_or("Token missing 'preferred_username' claim")?;

    Ok(token_data.claims.sub)
}

// Validator implementation
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

    // Validate the JWT token
    match validate_token(token_str) {
        Ok(username) => {
            info!("Token validated successfully for user '{}'", username);

            let username_cstr = match CString::new(username) {
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
            (*result).authorized = true;
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
        GucContext::Sighup,
        GucFlags::default(),
    );

    // Try to load JWKS keys if issuer_url is configured
    if let Some(issuer_cstring) = ISSUER_URL.get() {
        let issuer = issuer_cstring.to_str().unwrap_or("invalid_utf8");
        match load_jwks() {
            Ok(keys) => {
                let cache_size = keys.len();
                // Initialize the cache - this can only be done once
                if JWKS_CACHE.set(keys).is_ok() {
                    log!(
                        "pg_oidc_validator loaded successfully: cached {} JWKS key(s) from {}",
                        cache_size,
                        issuer
                    );
                } else {
                    warning!("Failed to initialize JWKS cache (already initialized?)");
                }
            }
            Err(e) => {
                warning!(
                    "pg_oidc_validator loaded but failed to fetch JWKS keys: {}. \
                     Check that pg_oidc_validator.issuer_url is configured correctly.",
                    e
                );
            }
        }
    } else {
        warning!(
            "pg_oidc_validator loaded but pg_oidc_validator.issuer_url is not configured. \
             Set it in postgresql.conf and reload configuration."
        );
    }
}

#[no_mangle]
pub extern "C" fn _PG_oauth_validator_module_init() -> *const OAuthValidatorCallbacks {
    log!("OAuth validator module init called for new connection");
    &CALLBACKS
}
