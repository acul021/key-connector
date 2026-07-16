use aes_gcm::aead::{Aead, Generate, Nonce, Payload};
use aes_gcm::{Aes256Gcm, KeyInit};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;

// Sealed values look like `v1|<nonce b64>|<ciphertext b64>`. The version tag
// leaves room for rotating the key or algorithm later.
const VERSION: &str = "v1";

// Seals key blobs with AES-256-GCM before they hit the database. The user id
// goes in as associated data, so a ciphertext copied into another user's row
// does not decrypt.
#[derive(Clone)]
pub struct KeyCipher {
    cipher: Aes256Gcm,
}

impl KeyCipher {
    pub fn new(key: &[u8]) -> Result<Self, String> {
        Aes256Gcm::new_from_slice(key)
            .map(|cipher| Self { cipher })
            .map_err(|_| format!("encryption key must be 32 bytes, got {}", key.len()))
    }

    // Plaintext rows predate encryption at rest.
    pub fn is_sealed(value: &str) -> bool {
        value.starts_with("v1|")
    }

    pub fn seal(&self, user_id: &str, plaintext: &str) -> Result<String, String> {
        let nonce = Nonce::<Aes256Gcm>::generate();
        let payload = Payload { msg: plaintext.as_bytes(), aad: user_id.as_bytes() };
        let ciphertext = self.cipher.encrypt(&nonce, payload).map_err(|e| e.to_string())?;
        Ok(format!("{VERSION}|{}|{}", BASE64.encode(nonce), BASE64.encode(&ciphertext)))
    }

    pub fn open(&self, user_id: &str, sealed: &str) -> Result<String, String> {
        let mut parts = sealed.splitn(3, '|');
        let (version, nonce_b64, ciphertext_b64) = match (parts.next(), parts.next(), parts.next()) {
            (Some(v), Some(n), Some(c)) => (v, n, c),
            _ => return Err("malformed sealed value".to_string()),
        };
        if version != VERSION {
            return Err(format!("unknown seal version '{version}'"));
        }
        let nonce = BASE64.decode(nonce_b64).map_err(|e| format!("bad nonce: {e}"))?;
        let nonce = Nonce::<Aes256Gcm>::try_from(nonce.as_slice())
            .map_err(|_| format!("bad nonce length {}", nonce.len()))?;
        let ciphertext = BASE64.decode(ciphertext_b64).map_err(|e| format!("bad ciphertext: {e}"))?;
        let payload = Payload { msg: &ciphertext, aad: user_id.as_bytes() };
        let plaintext = self
            .cipher
            .decrypt(&nonce, payload)
            .map_err(|_| "decryption failed (wrong key or tampered value)".to_string())?;
        String::from_utf8(plaintext).map_err(|e| format!("decrypted value is not utf-8: {e}"))
    }
}
