use sqlx::sqlite::SqlitePoolOptions;
use sqlx::SqlitePool;

// Maps the user id (JWT sub) to the stored key blob. The value is stored
// and returned verbatim, it is never parsed or used.
#[derive(Clone)]
pub struct KeyStore {
    pool: SqlitePool,
}

impl KeyStore {
    pub async fn connect(database_url: &str) -> Result<Self, sqlx::Error> {
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

        Ok(Self { pool })
    }

    pub async fn get(&self, user_id: &str) -> Result<Option<String>, sqlx::Error> {
        let row: Option<(String,)> = sqlx::query_as("SELECT key FROM user_keys WHERE user_id = ?")
            .bind(user_id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.map(|(k,)| k))
    }

    pub async fn set(&self, user_id: &str, key: &str) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO user_keys (user_id, key) VALUES (?, ?)
             ON CONFLICT(user_id) DO UPDATE SET key = excluded.key",
        )
        .bind(user_id)
        .bind(key)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}
