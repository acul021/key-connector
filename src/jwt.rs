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

#[derive(Clone)]
pub struct TokenVerifier {
    key: DecodingKey,
    validation: Validation,
}

impl TokenVerifier {
    pub fn from_config(cfg: &Config) -> Result<Self, String> {
        let pem = match &cfg.public_key {
            PublicKeySource::Inline(pem) => pem.clone().into_bytes(),
            PublicKeySource::Path(path) => std::fs::read(path)
                .map_err(|e| format!("failed to read public key file '{path}': {e}"))?,
        };

        let key = DecodingKey::from_rsa_pem(&pem)
            .map_err(|e| format!("identity public key is not a valid RSA PEM: {e}"))?;

        let mut validation = Validation::new(Algorithm::RS256);
        // Match Vaultwarden's decode_jwt: 30s leeway, validate exp + nbf, check issuer.
        validation.leeway = 30;
        validation.validate_exp = true;
        validation.validate_nbf = true;
        validation.set_issuer(std::slice::from_ref(&cfg.jwt_issuer));
        // Vaultwarden tokens don't carry an aud claim
        validation.validate_aud = false;

        Ok(Self { key, validation })
    }

    pub fn verify(&self, token: &str) -> Result<AccessClaims, ApiError> {
        // Vaultwarden strips whitespace before decoding, do the same
        let token: String = token.chars().filter(|c| !c.is_whitespace()).collect();
        decode::<AccessClaims>(&token, &self.key, &self.validation)
            .map(|data| data.claims)
            .map_err(|e| ApiError::InvalidToken(e.to_string()))
    }
}

pub fn bearer_from_header(value: Option<&str>) -> Result<&str, ApiError> {
    let value = value.ok_or(ApiError::MissingToken)?;
    let token = value.strip_prefix("Bearer ").or_else(|| value.strip_prefix("bearer "));
    token.map(str::trim).filter(|t| !t.is_empty()).ok_or(ApiError::MissingToken)
}
