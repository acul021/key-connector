use std::env;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;

/// Runtime configuration, read from environment variables.
///
/// All variables are prefixed with `KC_`.
#[derive(Debug, Clone)]
pub struct Config {
    /// Address to bind the HTTP server to, e.g. `0.0.0.0:8081`.
    pub bind_addr: String,
    /// sqlx database URL, e.g. `sqlite://keyconnector.db?mode=rwc`.
    pub database_url: String,
    /// Expected JWT issuer. For Vaultwarden this is `"<domain>|login"`,
    /// e.g. `https://vault.example.com|login`. Optional when the issuer can be
    /// discovered from an authority URL; overrides the discovered value if set.
    pub jwt_issuer: Option<String>,
    /// Where to obtain the RSA public key used to verify access tokens.
    pub public_key: PublicKeySource,
    /// 32 byte key used to seal the stored key blobs at rest.
    pub encryption_key: Vec<u8>,
    /// Origins allowed to call the connector from a browser. Empty means any
    /// origin is mirrored back, which is fine because auth is a bearer token,
    /// not a cookie.
    pub cors_allowed_origins: Vec<String>,
}

#[derive(Debug, Clone)]
pub enum PublicKeySource {
    /// Path to a PEM file holding the identity provider's RSA public key.
    Path(String),
    /// Inline PEM contents.
    Inline(String),
    /// Base URL of the identity provider, e.g. `https://vault.example.com/identity`.
    /// Issuer and signing key are fetched from its OIDC discovery document.
    Authority(String),
}

impl Config {
    pub fn from_env() -> Result<Self, String> {
        let bind_addr = env::var("KC_BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:8081".to_string());
        let database_url =
            env::var("KC_DATABASE_URL").unwrap_or_else(|_| "sqlite://keyconnector.db?mode=rwc".to_string());

        let jwt_issuer = env::var("KC_JWT_ISSUER").ok().filter(|s| !s.is_empty());

        let authority = env::var("KC_IDENTITY_AUTHORITY").ok().filter(|s| !s.is_empty());
        let public_key = match (env::var("KC_IDENTITY_PUBLIC_KEY_PATH"), env::var("KC_IDENTITY_PUBLIC_KEY_PEM"), authority) {
            (Ok(path), ..) if !path.is_empty() => PublicKeySource::Path(path),
            (_, Ok(pem), _) if !pem.is_empty() => PublicKeySource::Inline(pem),
            (_, _, Some(url)) => PublicKeySource::Authority(url.trim_end_matches('/').to_string()),
            _ => {
                return Err("Provide the identity provider via KC_IDENTITY_AUTHORITY \
                    (e.g. `https://vault.example.com/identity`), or its RSA public key via \
                    KC_IDENTITY_PUBLIC_KEY_PATH or KC_IDENTITY_PUBLIC_KEY_PEM"
                    .to_string())
            }
        };

        // Without discovery there is nowhere to get the issuer from.
        if jwt_issuer.is_none() && !matches!(public_key, PublicKeySource::Authority(_)) {
            return Err("KC_JWT_ISSUER is required (e.g. `https://vault.example.com|login`) \
                unless KC_IDENTITY_AUTHORITY is used"
                .to_string());
        }

        let encryption_key_b64 = match (env::var("KC_ENCRYPTION_KEY_PATH"), env::var("KC_ENCRYPTION_KEY")) {
            (Ok(path), _) if !path.is_empty() => std::fs::read_to_string(&path)
                .map_err(|e| format!("failed to read KC_ENCRYPTION_KEY_PATH '{path}': {e}"))?,
            (_, Ok(b64)) if !b64.is_empty() => b64,
            _ => {
                return Err("Provide a base64 encoded 32 byte key via KC_ENCRYPTION_KEY_PATH or \
                    KC_ENCRYPTION_KEY (generate one with `openssl rand -base64 32`)"
                    .to_string())
            }
        };
        let encryption_key = BASE64
            .decode(encryption_key_b64.trim())
            .map_err(|e| format!("encryption key is not valid base64: {e}"))?;
        if encryption_key.len() != 32 {
            return Err(format!("encryption key must decode to 32 bytes, got {}", encryption_key.len()));
        }

        let cors_allowed_origins = env::var("KC_CORS_ALLOWED_ORIGINS")
            .unwrap_or_default()
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(String::from)
            .collect();

        Ok(Self {
            bind_addr,
            database_url,
            jwt_issuer,
            public_key,
            encryption_key,
            cors_allowed_origins,
        })
    }
}
