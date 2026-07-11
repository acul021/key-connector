use std::env;

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
    /// e.g. `https://vault.example.com|login`.
    pub jwt_issuer: String,
    /// Where to obtain the RSA public key (PEM) used to verify access tokens.
    pub public_key: PublicKeySource,
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
}

impl Config {
    pub fn from_env() -> Result<Self, String> {
        let bind_addr = env::var("KC_BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:8081".to_string());
        let database_url =
            env::var("KC_DATABASE_URL").unwrap_or_else(|_| "sqlite://keyconnector.db?mode=rwc".to_string());

        let jwt_issuer = env::var("KC_JWT_ISSUER")
            .map_err(|_| "KC_JWT_ISSUER is required (e.g. `https://vault.example.com|login`)".to_string())?;

        let public_key = match (env::var("KC_IDENTITY_PUBLIC_KEY_PATH"), env::var("KC_IDENTITY_PUBLIC_KEY_PEM")) {
            (Ok(path), _) if !path.is_empty() => PublicKeySource::Path(path),
            (_, Ok(pem)) if !pem.is_empty() => PublicKeySource::Inline(pem),
            _ => {
                return Err("Provide the identity provider's RSA public key via \
                    KC_IDENTITY_PUBLIC_KEY_PATH or KC_IDENTITY_PUBLIC_KEY_PEM"
                    .to_string())
            }
        };

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
            cors_allowed_origins,
        })
    }
}
