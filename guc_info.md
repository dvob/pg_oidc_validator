# GUC Configuration for pg_oidc_validator

This document explains how the GUC (Grand Unified Configuration) system is used in pg_oidc_validator.

## Key Changes

### 1. **Added GUC Setting Declaration**
```rust
static ISSUER_URL: GucSetting<Option<&'static str>> = GucSetting::<Option<&'static str>>::new(None);
```

### 2. **Simplified Cache with RwLock**
The cache is now a simple `RwLock<HashMap>` initialized to empty, no `Lazy` needed since we populate it in `_PG_init()`:
```rust
static JWKS_CACHE: RwLock<HashMap<String, DecodingKey>> = RwLock::new(HashMap::new());
```

### 3. **Registered GUC in _PG_init()**
```rust
GucRegistry::define_string_guc(
    "pg_oidc_validator.issuer_url",
    "OIDC issuer URL for JWT token validation",
    "The base URL of the OIDC provider (e.g., https://accounts.google.com)",
    &ISSUER_URL,
    GucContext::Sighup,  // Can be reloaded with SIGHUP (pg_reload_conf())
    GucFlags::default(),
);
```

### 4. **Updated load_jwks() to use GUC**
Now reads from the GUC setting instead of environment variable:
```rust
let issuer_url = ISSUER_URL.get()
    .ok_or("pg_oidc_validator.issuer_url is not configured")?;
```

### 5. **Updated validate_token() for RwLock**
Uses read lock to access the cache:
```rust
let cache = JWKS_CACHE.read()
    .map_err(|e| format!("Failed to acquire cache read lock: {}", e))?;
let key = cache.get(&kid)...
```

## Configuration

Now you can configure it in **postgresql.conf**:

```conf
# Add to postgresql.conf
shared_preload_libraries = 'pg_oidc_validator'
pg_oidc_validator.issuer_url = 'https://your-oidc-provider.com'
```

Or via SQL:
```sql
ALTER SYSTEM SET pg_oidc_validator.issuer_url = 'https://your-oidc-provider.com';
SELECT pg_reload_conf();  -- Reload without restart (since it's SIGHUP)
```

## GucContext Levels

I used `GucContext::Sighup` which means:
- ✅ Can be changed in postgresql.conf
- ✅ Reloaded with `pg_reload_conf()` or `SIGHUP` signal
- ❌ Not changeable per-session
- ❌ Not changeable per-transaction

Other options you could use:
- `GucContext::Postmaster` - Requires PostgreSQL restart (like shared_preload_libraries)
- `GucContext::Suset` - Superuser can change per-session
- `GucContext::User` - Any user can change per-session

## Benefits

1. **No environment variables needed** - Pure PostgreSQL configuration
2. **Reloadable** - Can change issuer URL with `pg_reload_conf()`
3. **Visible in pg_settings** - Shows up in `SELECT * FROM pg_settings WHERE name LIKE 'pg_oidc%';`
4. **Documented** - The description appears in PostgreSQL's configuration system

## Note on Cache Reloading

The current implementation loads JWKS keys once at startup. If you want to **reload keys when the GUC changes**, you would need to add a GUC assign hook. Let me know if you want that feature!
