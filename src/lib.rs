use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use once_cell::sync::Lazy;
use pgrx::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::ffi::CString;
use std::os::raw::{c_char, c_int};

::pgrx::pg_module_magic!();

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

// Cache for JWKS keys
static JWKS_CACHE: Lazy<HashMap<String, DecodingKey>> = Lazy::new(|| match load_jwks() {
    Ok(keys) => keys,
    Err(e) => {
        log!("Failed to load JWKS: {}", e);
        HashMap::new()
    }
});

fn load_jwks() -> Result<HashMap<String, DecodingKey>, Box<dyn std::error::Error>> {
    let issuer_url = std::env::var("ISSUER_URL")?;

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

    let key = JWKS_CACHE
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
pub extern "C" fn _PG_oauth_validator_module_init() -> *const OAuthValidatorCallbacks {
    log!("load validator");
    &CALLBACKS
}
