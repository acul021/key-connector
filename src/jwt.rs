use std::sync::{Arc, RwLock};
use std::time::Duration;

use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::Deserialize;

use crate::config::{Config, PublicKeySource};
use crate::error::ApiError;

// The claims we actually care about, serde ignores the rest
#[derive(Debug, Deserialize)]
pub struct AccessClaims {
    // the user's GUID, used as the storage key
    pub sub: String,
}

#[derive(Deserialize)]
struct DiscoveryDocument {
    issuer: String,
    jwks_uri: String,
}

#[derive(Deserialize)]
struct JwkSet {
    keys: Vec<Jwk>,
}

#[derive(Deserialize)]
pub(crate) struct Jwk {
    pub(crate) kty: String,
    #[serde(rename = "use")]
    pub(crate) usage: Option<String>,
    pub(crate) n: Option<String>,
    pub(crate) e: Option<String>,
}

const JWKS_REFRESH_INTERVAL: Duration = Duration::from_secs(600);

#[derive(Clone)]
pub struct TokenVerifier {
    key: Arc<RwLock<DecodingKey>>,
    validation: Validation,
}

impl TokenVerifier {
    pub async fn from_config(cfg: &Config) -> Result<Self, String> {
        let mut refresh = None;

        let (key, discovered_issuer) = match &cfg.public_key {
            PublicKeySource::Inline(pem) => (key_from_pem(pem.as_bytes())?, None),
            PublicKeySource::Path(path) => {
                let pem = std::fs::read(path)
                    .map_err(|e| format!("failed to read public key file '{path}': {e}"))?;
                (key_from_pem(&pem)?, None)
            }
            PublicKeySource::Authority(authority) => {
                let client = reqwest::Client::new();
                let discovery = wait_for_discovery(&client, authority).await?;
                let key = fetch_jwks(&client, &discovery.jwks_uri).await?;
                tracing::info!(issuer = %discovery.issuer, jwks_uri = %discovery.jwks_uri, "discovered identity provider");
                refresh = Some((client, discovery.jwks_uri));
                (key, Some(discovery.issuer))
            }
        };

        // An explicitly configured issuer wins over the discovered one.
        let issuer = cfg
            .jwt_issuer
            .clone()
            .or(discovered_issuer)
            .ok_or("KC_JWT_ISSUER is required when the key is given as a PEM")?;

        let mut validation = Validation::new(Algorithm::RS256);
        // Match Vaultwarden's decode_jwt: 30s leeway, validate exp + nbf, check issuer.
        validation.leeway = 30;
        validation.validate_exp = true;
        validation.validate_nbf = true;
        validation.set_issuer(&[issuer]);
        // Vaultwarden tokens don't carry an aud claim
        validation.validate_aud = false;

        let key = Arc::new(RwLock::new(key));

        // Refresh the JWKS in the background so a key rotation on the identity
        // provider doesn't need a restart.
        if let Some((client, jwks_uri)) = refresh {
            let key = Arc::clone(&key);
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(JWKS_REFRESH_INTERVAL).await;
                    match fetch_jwks(&client, &jwks_uri).await {
                        Ok(new_key) => *key.write().unwrap() = new_key,
                        Err(e) => tracing::warn!(error = %e, "jwks refresh failed, keeping the current key"),
                    }
                }
            });
        }

        Ok(Self { key, validation })
    }

    pub fn verify(&self, token: &str) -> Result<AccessClaims, ApiError> {
        // Vaultwarden strips whitespace before decoding, do the same
        let token: String = token.chars().filter(|c| !c.is_whitespace()).collect();
        let key = self.key.read().unwrap();
        decode::<AccessClaims>(&token, &key, &self.validation)
            .map(|data| data.claims)
            .map_err(|e| ApiError::InvalidToken(e.to_string()))
    }
}

fn key_from_pem(pem: &[u8]) -> Result<DecodingKey, String> {
    DecodingKey::from_rsa_pem(pem).map_err(|e| format!("identity public key is not a valid RSA PEM: {e}"))
}

pub(crate) fn key_from_jwk(jwk: &Jwk) -> Result<DecodingKey, String> {
    match (&jwk.n, &jwk.e) {
        (Some(n), Some(e)) => {
            DecodingKey::from_rsa_components(n, e).map_err(|e| format!("bad RSA components in JWK: {e}"))
        }
        _ => Err("JWK is missing the RSA n/e components".to_string()),
    }
}

// The identity provider may well come up after us, keep trying for a while.
async fn wait_for_discovery(client: &reqwest::Client, authority: &str) -> Result<DiscoveryDocument, String> {
    let url = format!("{authority}/.well-known/openid-configuration");
    let mut last_err = String::new();
    for attempt in 0..60 {
        if attempt > 0 {
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
        match fetch_json::<DiscoveryDocument>(client, &url).await {
            Ok(doc) => return Ok(doc),
            Err(e) => {
                tracing::warn!(error = %e, url, "identity provider not reachable yet");
                last_err = e;
            }
        }
    }
    Err(format!("giving up on '{url}': {last_err}"))
}

async fn fetch_jwks(client: &reqwest::Client, jwks_uri: &str) -> Result<DecodingKey, String> {
    let set: JwkSet = fetch_json(client, jwks_uri).await?;
    let jwk = set
        .keys
        .iter()
        .find(|k| k.kty == "RSA" && k.usage.as_deref().unwrap_or("sig") == "sig")
        .ok_or_else(|| format!("no RSA signing key in the JWKS at '{jwks_uri}'"))?;
    key_from_jwk(jwk)
}

async fn fetch_json<T: serde::de::DeserializeOwned>(client: &reqwest::Client, url: &str) -> Result<T, String> {
    client
        .get(url)
        .send()
        .await
        .map_err(|e| e.to_string())?
        .error_for_status()
        .map_err(|e| e.to_string())?
        .json()
        .await
        .map_err(|e| e.to_string())
}

pub fn bearer_from_header(value: Option<&str>) -> Result<&str, ApiError> {
    let value = value.ok_or(ApiError::MissingToken)?;
    let token = value.strip_prefix("Bearer ").or_else(|| value.strip_prefix("bearer "));
    token.map(str::trim).filter(|t| !t.is_empty()).ok_or(ApiError::MissingToken)
}
