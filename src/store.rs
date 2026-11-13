use std::str::FromStr;
use std::time::Duration;

use sqlx::postgres::{PgConnectOptions, PgConnection, PgPoolOptions};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::{Connection, PgPool, SqlitePool};

use crate::crypto::KeyCipher;

// Maps the user id (JWT sub) to the stored key blob. The value is sealed at
// rest and returned verbatim to the client, it is never parsed or used.
#[derive(Clone)]
pub struct KeyStore {
    pool: Pool,
    cipher: KeyCipher,
}

#[derive(Clone)]
enum Pool {
    Sqlite(SqlitePool),
    Postgres(PgPool),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    Sqlite,
    Postgres,
}

const SQLITE_HINT: &str = "The database file and the directory holding it must be writable by the user \
    running key-connector (uid 10001 in the Docker image)";

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error(transparent)]
    Db(#[from] sqlx::Error),
    // Holds the scheme only when it looks like one, never the raw input.
    #[error("unsupported database URL scheme{}, use sqlite: or postgres(ql)://", .0.as_ref().map(|s| format!(" '{s}'")).unwrap_or_default())]
    UnsupportedScheme(Option<String>),
    #[error("{0}")]
    InvalidUrl(&'static str),
    #[error("{0}. The directory must exist. {SQLITE_HINT}, and the URL needs `?mode=rwc` to create the file on first start")]
    SqliteCantOpen(sqlx::Error),
    #[error("{0}. The database is read-only. {SQLITE_HINT}")]
    SqliteReadOnly(sqlx::Error),
    #[error("timed out after {}s connecting to PostgreSQL", PG_CONNECT_TIMEOUT.as_secs())]
    PgConnectTimeout,
    #[error("crypto error: {0}")]
    Crypto(String),
}

const CREATE_TABLE: &str = "CREATE TABLE IF NOT EXISTS user_keys (
        user_id TEXT PRIMARY KEY NOT NULL,
        key     TEXT NOT NULL
    )";

// Serialises the schema setup of several instances starting at once against
// the same Postgres database. Concurrent CREATE TABLE IF NOT EXISTS can fail
// there with a unique violation on pg_type.
const PG_SCHEMA_LOCK: i64 = 0x6b63_7363_6865_6d61; // "kcschema"

const PG_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
// Requests fail after this long when the database hangs, instead of sqlx's
// default of 30s.
const PG_ACQUIRE_TIMEOUT: Duration = Duration::from_secs(5);

// Runs the same block against whichever pool is configured. The queries
// below use `$1`-style placeholders, which both Postgres and sqlx's SQLite
// driver accept, and only TEXT columns, so the SQL is shared.
macro_rules! with_pool {
    ($pool:expr, $p:ident => $body:expr) => {
        match $pool {
            Pool::Sqlite($p) => $body,
            Pool::Postgres($p) => $body,
        }
    };
}

// RFC 3986 scheme syntax. Anything else is not echoed back in messages.
fn is_scheme(s: &str) -> bool {
    let mut chars = s.chars();
    chars.next().is_some_and(|c| c.is_ascii_alphabetic())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
}

/// Checks the URL and picks the backend. Returns the URL with the scheme in
/// lower case, sqlx only recognises lower case schemes.
pub fn normalize_url(database_url: &str) -> Result<(Backend, String), StoreError> {
    let Some((scheme, rest)) = database_url.split_once(':').filter(|(s, _)| is_scheme(s)) else {
        return Err(StoreError::UnsupportedScheme(None));
    };
    let scheme = scheme.to_ascii_lowercase();
    let backend = match scheme.as_str() {
        "sqlite" => Backend::Sqlite,
        "postgres" | "postgresql" => {
            if !rest.starts_with("//") {
                return Err(StoreError::InvalidUrl(
                    "PostgreSQL URLs must start with postgres:// or postgresql://",
                ));
            }
            // An unencoded '#' turns the rest of the URL into a fragment and
            // silently changes what gets parsed as user, password and host.
            if rest.contains('#') {
                return Err(StoreError::InvalidUrl(
                    "the database URL contains '#', percent-encode it as %23 (e.g. in the password)",
                ));
            }
            Backend::Postgres
        }
        _ => return Err(StoreError::UnsupportedScheme(Some(scheme))),
    };
    Ok((backend, format!("{scheme}:{rest}")))
}

/// Returns the URL in a form that is safe to log. Fails closed: SQLite URLs
/// are shown as written (they hold no credentials), PostgreSQL URLs only as
/// `scheme://[user[:***]@]host[:port]/dbname[?sslmode=...]`. If anything
/// doesn't parse cleanly, at most the scheme is shown.
pub fn redact_url(database_url: &str) -> String {
    let Some((scheme, _)) = database_url.split_once(':').filter(|(s, _)| is_scheme(s)) else {
        return "<redacted>".to_string();
    };
    let shown = match scheme.to_ascii_lowercase().as_str() {
        "sqlite" if !database_url.contains('@') => Some(database_url.to_string()),
        "postgres" | "postgresql" => redact_pg_url(scheme, database_url),
        _ => None,
    };
    shown.unwrap_or_else(|| format!("{scheme}:<redacted>"))
}

fn redact_pg_url(scheme: &str, database_url: &str) -> Option<String> {
    if !database_url[scheme.len() + 1..].starts_with("//") || database_url.contains('#') {
        return None;
    }
    let url = url::Url::parse(database_url).ok()?;

    // An encoded password has no '@'. If there is any '@' besides the one
    // ending the userinfo, the parser may have split the URL in the wrong
    // place, e.g. at a '/' or '?' inside the password.
    let has_userinfo = !url.username().is_empty() || url.password().is_some();
    if database_url.matches('@').count() != usize::from(has_userinfo) {
        return None;
    }
    let path = url.path();
    if path.len() > 1 && path[1..].contains('/') {
        return None;
    }

    let mut out = format!("{scheme}://");
    if has_userinfo {
        out.push_str(url.username());
        if url.password().is_some() {
            out.push_str(":***");
        }
        out.push('@');
    }
    out.push_str(url.host_str().unwrap_or_default());
    if let Some(port) = url.port() {
        out.push_str(&format!(":{port}"));
    }
    out.push_str(path);
    // Not secret and useful when debugging TLS problems. Only known values.
    let ssl_mode = url.query_pairs().find(|(k, _)| k == "sslmode" || k == "ssl-mode").map(|(_, v)| v);
    if let Some(mode) = ssl_mode.filter(|v| {
        ["disable", "allow", "prefer", "require", "verify-ca", "verify-full"].contains(&v.as_ref())
    }) {
        out.push_str(&format!("?sslmode={mode}"));
    }
    Some(out)
}

/// The message logged when the store can't be opened at startup.
pub fn startup_error(database_url: &str, e: &StoreError) -> String {
    format!("failed to open database '{}': {e}", redact_url(database_url))
}

// Adds a hint to the SQLite errors a wrong path or file permissions cause.
// sqlx reports the extended result code, the primary code is its low byte.
fn sqlite_error(e: sqlx::Error) -> StoreError {
    let code = match &e {
        sqlx::Error::Database(db) => db.code().and_then(|c| c.parse::<i32>().ok()).map(|c| c & 0xff),
        _ => None,
    };
    match code {
        Some(14) => StoreError::SqliteCantOpen(e), // SQLITE_CANTOPEN
        Some(8) => StoreError::SqliteReadOnly(e),  // SQLITE_READONLY
        _ => StoreError::Db(e),
    }
}

async fn connect_sqlite(url: &str) -> Result<SqlitePool, StoreError> {
    let opts = SqliteConnectOptions::from_str(url)?;
    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect_with(opts)
        .await
        .map_err(sqlite_error)?;
    sqlx::query(CREATE_TABLE).execute(&pool).await.map_err(sqlite_error)?;

    // SQLite opens a file it can't write read-only without complaint, and
    // CREATE TABLE IF NOT EXISTS doesn't write when the table exists. Make
    // one real write that is rolled back, so a read-only file or directory
    // fails here and not on the first POST. The write dirties a page, which
    // also makes SQLite create the rollback journal next to the file.
    let mut conn = pool.acquire().await.map_err(sqlite_error)?;
    let mut tx = conn.begin().await.map_err(sqlite_error)?;
    sqlx::query("CREATE TABLE kc_write_check (x INTEGER)")
        .execute(&mut *tx)
        .await
        .map_err(sqlite_error)?;
    tx.rollback().await.map_err(sqlite_error)?;
    Ok(pool)
}

pub(crate) fn pg_pool_options() -> PgPoolOptions {
    PgPoolOptions::new().max_connections(5).acquire_timeout(PG_ACQUIRE_TIMEOUT)
}

async fn connect_postgres(url: &str) -> Result<PgPool, StoreError> {
    let opts = PgConnectOptions::from_str(url)?;

    // One direct connection first. The pool retries until its acquire timeout
    // and then reports only "pool timed out", which hides errors like
    // "connection refused" or a failed login.
    let mut conn = tokio::time::timeout(PG_CONNECT_TIMEOUT, PgConnection::connect_with(&opts))
        .await
        .map_err(|_| StoreError::PgConnectTimeout)??;
    let mut tx = conn.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(PG_SCHEMA_LOCK)
        .execute(&mut *tx)
        .await?;
    // Postgres checks the CREATE privilege on the schema before it looks at
    // IF NOT EXISTS. Skip the statement when the table is already there, so
    // a role without CREATE (the default on `public` since PostgreSQL 15)
    // can start against a table created beforehand. to_regclass resolves
    // the name through search_path, like the other queries.
    let (exists,): (bool,) = sqlx::query_as("SELECT to_regclass('user_keys') IS NOT NULL")
        .fetch_one(&mut *tx)
        .await?;
    if !exists {
        sqlx::query(CREATE_TABLE).execute(&mut *tx).await?;
    }
    tx.commit().await?;
    conn.close().await?;

    Ok(pg_pool_options().connect_lazy_with(opts))
}

impl KeyStore {
    pub async fn connect(database_url: &str, cipher: KeyCipher) -> Result<Self, StoreError> {
        let (backend, url) = normalize_url(database_url)?;
        let pool = match backend {
            Backend::Sqlite => Pool::Sqlite(connect_sqlite(&url).await?),
            Backend::Postgres => Pool::Postgres(connect_postgres(&url).await?),
        };

        let store = Self { pool, cipher };
        store.seal_plaintext_rows().await?;
        Ok(store)
    }

    // Rows written before encryption at rest existed are plaintext. Seal them
    // once at startup; the table holds one row per SSO user, so a full scan
    // is cheap.
    async fn seal_plaintext_rows(&self) -> Result<(), StoreError> {
        let rows: Vec<(String, String)> = with_pool!(&self.pool, p => {
            sqlx::query_as("SELECT user_id, key FROM user_keys").fetch_all(p).await
        })?;
        self.seal_rows(rows).await
    }

    // Each UPDATE only applies if the row still holds the plaintext that was
    // read. Another instance may have stored a new key in the meantime, that
    // one must not be replaced with the sealed old value.
    pub(crate) async fn seal_rows(&self, rows: Vec<(String, String)>) -> Result<(), StoreError> {
        let mut sealed_count = 0;
        for (user_id, key) in rows {
            if KeyCipher::is_sealed(&key) {
                continue;
            }
            let sealed = self.cipher.seal(&user_id, &key).map_err(StoreError::Crypto)?;
            let affected = with_pool!(&self.pool, p => {
                sqlx::query("UPDATE user_keys SET key = $1 WHERE user_id = $2 AND key = $3")
                    .bind(&sealed)
                    .bind(&user_id)
                    .bind(&key)
                    .execute(p)
                    .await
                    .map(|r| r.rows_affected())
            })?;
            sealed_count += affected;
        }
        if sealed_count > 0 {
            tracing::info!(count = sealed_count, "sealed plaintext key rows");
        }
        Ok(())
    }

    pub async fn get(&self, user_id: &str) -> Result<Option<String>, StoreError> {
        let row: Option<(String,)> = with_pool!(&self.pool, p => {
            sqlx::query_as("SELECT key FROM user_keys WHERE user_id = $1")
                .bind(user_id)
                .fetch_optional(p)
                .await
        })?;
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
        with_pool!(&self.pool, p => {
            sqlx::query(
                "INSERT INTO user_keys (user_id, key) VALUES ($1, $2)
                 ON CONFLICT (user_id) DO UPDATE SET key = excluded.key",
            )
            .bind(user_id)
            .bind(&sealed)
            .execute(p)
            .await
            .map(|_| ())
        })?;
        Ok(())
    }
}
