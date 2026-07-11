use sqlx::sqlite::SqlitePoolOptions;
use sqlx::SqlitePool;

use crate::crypto::KeyCipher;

// Maps the user id (JWT sub) to the stored key blob. The value is sealed at
// rest and returned verbatim to the client, it is never parsed or used.
#[derive(Clone)]
pub struct KeyStore {
    pool: SqlitePool,
    cipher: KeyCipher,
}

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error(transparent)]
    Db(#[from] sqlx::Error),
    #[error("crypto error: {0}")]
    Crypto(String),
}

impl KeyStore {
    pub async fn connect(database_url: &str, cipher: KeyCipher) -> Result<Self, StoreError> {
        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect(database_url)
            .await?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS user_keys (
                user_id TEXT PRIMARY KEY NOT NULL,
                key     TEXT NOT NULL
            )",
        )
        .execute(&pool)
        .await?;

        let store = Self { pool, cipher };
        store.seal_plaintext_rows().await?;
        Ok(store)
    }

    // Rows written before encryption at rest existed are plaintext. Seal them
    // once at startup; the table holds one row per SSO user, so a full scan
    // is cheap.
    async fn seal_plaintext_rows(&self) -> Result<(), StoreError> {
        let rows: Vec<(String, String)> = sqlx::query_as("SELECT user_id, key FROM user_keys")
            .fetch_all(&self.pool)
            .await?;

        let mut sealed_count = 0;
        for (user_id, key) in rows {
            if KeyCipher::is_sealed(&key) {
                continue;
            }
            let sealed = self.cipher.seal(&user_id, &key).map_err(StoreError::Crypto)?;
            sqlx::query("UPDATE user_keys SET key = ? WHERE user_id = ?")
                .bind(sealed)
                .bind(user_id)
                .execute(&self.pool)
                .await?;
            sealed_count += 1;
        }
        if sealed_count > 0 {
            tracing::info!(count = sealed_count, "sealed plaintext key rows");
        }
        Ok(())
    }

    pub async fn get(&self, user_id: &str) -> Result<Option<String>, StoreError> {
        let row: Option<(String,)> = sqlx::query_as("SELECT key FROM user_keys WHERE user_id = ?")
            .bind(user_id)
            .fetch_optional(&self.pool)
            .await?;
        match row {
            None => Ok(None),
            Some((stored,)) => {
                let key = self.cipher.open(user_id, &stored).map_err(StoreError::Crypto)?;
                Ok(Some(key))
            }
        }
    }

    pub async fn set(&self, user_id: &str, key: &str) -> Result<(), StoreError> {
        let sealed = self.cipher.seal(user_id, key).map_err(StoreError::Crypto)?;
        sqlx::query(
            "INSERT INTO user_keys (user_id, key) VALUES (?, ?)
             ON CONFLICT(user_id) DO UPDATE SET key = excluded.key",
        )
        .bind(user_id)
        .bind(sealed)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}
