// End to end tests against the real router, with real RS256 signed tokens.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use jsonwebtoken::{encode, EncodingKey, Header};
use serde::Serialize;
use tower::ServiceExt; // for `oneshot`

use crate::config::{Config, PublicKeySource};
use crate::crypto::KeyCipher;
use crate::jwt::TokenVerifier;
use crate::routes::{router, AppState};
use crate::store::{normalize_url, redact_url, startup_error, Backend, KeyStore};

const ISSUER: &str = "https://vault.example.com|login";

#[derive(Serialize)]
struct TestClaims {
    sub: String,
    iss: String,
    nbf: i64,
    exp: i64,
}

fn priv_pem() -> Vec<u8> {
    include_bytes!("../tests/fixtures/test_priv.pem").to_vec()
}

fn pub_pem() -> String {
    include_str!("../tests/fixtures/test_pub.pem").to_string()
}

fn sign(sub: &str, iss: &str, exp_offset: i64) -> String {
    let now = chrono::Utc::now().timestamp();
    let claims = TestClaims {
        sub: sub.to_string(),
        iss: iss.to_string(),
        nbf: now - 10,
        exp: now + exp_offset,
    };
    let key = EncodingKey::from_rsa_pem(&priv_pem()).unwrap();
    encode(&Header::new(jsonwebtoken::Algorithm::RS256), &claims, &key).unwrap()
}

async fn test_app() -> axum::Router {
    let cfg = Config {
        bind_addr: "127.0.0.1:0".into(),
        database_url: "sqlite::memory:".into(),
        jwt_issuer: Some(ISSUER.into()),
        public_key: PublicKeySource::Inline(pub_pem()),
        encryption_key: vec![0x42; 32],
        cors_allowed_origins: vec![],
    };
    let verifier = TokenVerifier::from_config(&cfg).await.unwrap();
    let cipher = KeyCipher::new(&cfg.encryption_key).unwrap();
    let store = KeyStore::connect(&cfg.database_url, cipher).await.unwrap();
    router(AppState { verifier, store }, &cfg.cors_allowed_origins)
}

async fn body_string(resp: axum::response::Response) -> String {
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    String::from_utf8(bytes.to_vec()).unwrap()
}

#[tokio::test]
async fn alive_is_unauthenticated() {
    let app = test_app().await;
    let resp = app
        .oneshot(Request::builder().uri("/alive").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn post_then_get_roundtrips_the_key() {
    let app = test_app().await;
    let token = sign("user-123", ISSUER, 3600);

    // POST /user-keys
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/user-keys")
                .header("Authorization", format!("Bearer {token}"))
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"key":"AAAABBBBCCCC=="}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // GET /user-keys returns what we stored
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/user-keys")
                .header("Authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body_string(resp).await, r#"{"key":"AAAABBBBCCCC=="}"#);
}

#[tokio::test]
async fn preflight_gets_cors_headers() {
    let app = test_app().await;
    let resp = app
        .oneshot(
            Request::builder()
                .method("OPTIONS")
                .uri("/user-keys")
                .header("Origin", "https://vault.example.com")
                .header("Access-Control-Request-Method", "POST")
                .header(
                    "Access-Control-Request-Headers",
                    "authorization,bitwarden-client-name,bitwarden-client-version,cache-control,pragma",
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.headers().get("access-control-allow-origin").unwrap(),
        "https://vault.example.com"
    );
    // The connector mirrors whatever headers the preflight asks for.
    let allowed = resp.headers().get("access-control-allow-headers").unwrap().to_str().unwrap();
    assert!(allowed.contains("cache-control"), "allowed headers: {allowed}");
    assert!(allowed.contains("bitwarden-client-name"), "allowed headers: {allowed}");
}

#[tokio::test]
async fn get_without_token_is_unauthorized() {
    let app = test_app().await;
    let resp = app
        .oneshot(Request::builder().uri("/user-keys").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn wrong_issuer_is_rejected() {
    let app = test_app().await;
    let token = sign("user-123", "https://evil.example.com|login", 3600);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/user-keys")
                .header("Authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn expired_token_is_rejected() {
    let app = test_app().await;
    let token = sign("user-123", ISSUER, -3600); // already expired
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/user-keys")
                .header("Authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[test]
fn jwk_matches_the_pem_fixture() {
    // n/e of tests/fixtures/test_pub.pem, as Vaultwarden would publish them
    // in its JWKS.
    let jwk = crate::jwt::Jwk {
        kty: "RSA".into(),
        usage: Some("sig".into()),
        n: Some(
            "lcN9Hcvf8PeQUI9y-c7TGdUhyCKfeUSEyPlpMPrkDrRBzkWuu1Nx8qHIu2qvhd81oUD8BEpb10NKnaGtL0Q3bououv6sxxey4esR6WkBxkoLrJBI6rNHR6QBv-_OCm8SbIBsRiS_o5xTzQduN0INonUuceQoS2I__uAN9GH0sBZa9Uj-_PnmyRwIQp_cL15RIcFJIW0vhFhX-t7e0iy3bvsNCGleBwVgTzSO14saLBLQ5o8GdREYGYr-wDjd7gIOiunaXBf1ev-p7u_G5aKUAADAEhVXcTWlUY0NJIQN8enmItEAscWH-sZeJjxFCyZjn7IERYERqCmR4-B6o-cdkQ"
                .into(),
        ),
        e: Some("AQAB".into()),
    };
    let key = crate::jwt::key_from_jwk(&jwk).unwrap();

    // A token signed with the fixture private key verifies against it.
    let token = sign("user-123", ISSUER, 3600);
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
    validation.set_issuer(&[ISSUER]);
    let decoded = jsonwebtoken::decode::<serde_json::Value>(&token, &key, &validation).unwrap();
    assert_eq!(decoded.claims["sub"], "user-123");
}

#[test]
fn seal_open_roundtrips() {
    let cipher = KeyCipher::new(&[0x42; 32]).unwrap();
    let sealed = cipher.seal("user-123", "AAAABBBBCCCC==").unwrap();
    assert!(KeyCipher::is_sealed(&sealed));
    assert!(!sealed.contains("AAAABBBBCCCC=="));
    assert_eq!(cipher.open("user-123", &sealed).unwrap(), "AAAABBBBCCCC==");
}

#[test]
fn sealed_value_is_bound_to_the_user() {
    let cipher = KeyCipher::new(&[0x42; 32]).unwrap();
    let sealed = cipher.seal("alice", "alice-secret").unwrap();
    assert!(cipher.open("bob", &sealed).is_err());
}

#[test]
fn wrong_key_and_tampering_are_rejected() {
    let cipher = KeyCipher::new(&[0x42; 32]).unwrap();
    let sealed = cipher.seal("user-123", "secret").unwrap();

    let other = KeyCipher::new(&[0x43; 32]).unwrap();
    assert!(other.open("user-123", &sealed).is_err());

    let tampered = format!("{}AA==", &sealed[..sealed.len() - 4]);
    assert!(cipher.open("user-123", &tampered).is_err());
    assert!(cipher.open("user-123", "not-sealed-at-all").is_err());
}

#[tokio::test]
async fn plaintext_rows_are_sealed_on_startup() {
    // Simulates a database written before encryption at rest existed.
    let db_path = std::env::temp_dir().join(format!("kc-migration-test-{}.db", std::process::id()));
    let _ = std::fs::remove_file(&db_path);
    let url = format!("sqlite://{}?mode=rwc", db_path.display());

    let pool = sqlx::sqlite::SqlitePoolOptions::new().connect(&url).await.unwrap();
    sqlx::query("CREATE TABLE user_keys (user_id TEXT PRIMARY KEY NOT NULL, key TEXT NOT NULL)")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO user_keys VALUES ('legacy-user', 'legacy-plaintext-key')")
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;

    let store = KeyStore::connect(&url, KeyCipher::new(&[0x42; 32]).unwrap()).await.unwrap();
    assert_eq!(store.get("legacy-user").await.unwrap().unwrap(), "legacy-plaintext-key");

    // The row on disk is sealed now.
    let pool = sqlx::sqlite::SqlitePoolOptions::new().connect(&url).await.unwrap();
    let (stored,): (String,) = sqlx::query_as("SELECT key FROM user_keys WHERE user_id = 'legacy-user'")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(KeyCipher::is_sealed(&stored));
    assert!(!stored.contains("legacy-plaintext-key"));
    pool.close().await;

    let _ = std::fs::remove_file(&db_path);
}

#[tokio::test]
async fn users_cannot_read_each_others_keys() {
    let app = test_app().await;
    let alice = sign("alice", ISSUER, 3600);
    let bob = sign("bob", ISSUER, 3600);

    // Alice stores a key.
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/user-keys")
                .header("Authorization", format!("Bearer {alice}"))
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"key":"alice-secret"}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    // Bob has no key of his own yet -> 404, and never sees Alice's.
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/user-keys")
                .header("Authorization", format!("Bearer {bob}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

fn temp_path(name: &str) -> std::path::PathBuf {
    static SEQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let n = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    std::env::temp_dir().join(format!("kc-{name}-{}-{n}", std::process::id()))
}

fn test_cipher() -> KeyCipher {
    KeyCipher::new(&[0x42; 32]).unwrap()
}

// The full line main() logs when the store can't be opened.
async fn startup_message(url: &str) -> String {
    match KeyStore::connect(url, test_cipher()).await {
        Ok(_) => panic!("{url} should not open"),
        Err(e) => startup_error(url, &e),
    }
}

#[test]
fn database_url_scheme_picks_the_backend() {
    let backend = |url| normalize_url(url).unwrap().0;
    assert_eq!(backend("sqlite::memory:"), Backend::Sqlite);
    assert_eq!(backend("sqlite://keyconnector.db?mode=rwc"), Backend::Sqlite);
    assert_eq!(backend("sqlite:///data/keyconnector.db?mode=rwc"), Backend::Sqlite);
    assert_eq!(backend("postgres://kc@db/kc"), Backend::Postgres);
    assert_eq!(backend("postgresql://kc:pw@db:5432/kc?sslmode=require"), Backend::Postgres);
}

#[test]
fn database_url_scheme_is_lowercased() {
    assert_eq!(normalize_url("SQLite:kc.db").unwrap(), (Backend::Sqlite, "sqlite:kc.db".to_string()));
    assert_eq!(
        normalize_url("PostgreSQL://kc@db/kc").unwrap(),
        (Backend::Postgres, "postgresql://kc@db/kc".to_string())
    );
}

#[tokio::test]
async fn uppercase_sqlite_scheme_opens_the_right_file() {
    let dir = temp_path("upper");
    std::fs::create_dir_all(&dir).unwrap();
    let db_path = dir.join("kc.db");
    let url = format!("SQLITE://{}?mode=rwc", db_path.display());

    let store = KeyStore::connect(&url, test_cipher()).await.unwrap();
    store.set("user-1", "k").await.unwrap();
    assert!(db_path.exists());
    assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn unknown_database_scheme_is_rejected() {
    for url in ["mysql://kc:pw@db/kc", "keyconnector.db", "file:keyconnector.db"] {
        let err = normalize_url(url).unwrap_err().to_string();
        assert!(err.contains("unsupported database URL scheme"), "{url}: {err}");
        assert!(err.contains("use sqlite: or postgres(ql)://"), "{url}: {err}");
    }
    let msg = startup_message("mysql://kc:Secret@db/kc").await;
    assert_eq!(
        msg,
        "failed to open database 'mysql:<redacted>': unsupported database URL scheme 'mysql', \
         use sqlite: or postgres(ql)://"
    );
}

#[tokio::test]
async fn startup_error_never_shows_the_password() {
    // The full logged line, for URLs that fail before reaching the network.
    let cases = [
        ("kc:Secret@db/kc", "failed to open database 'kc:<redacted>': unsupported database URL scheme 'kc', use sqlite: or postgres(ql)://"),
        ("host=db user=kc password=Secret dbname=kc", "failed to open database '<redacted>': unsupported database URL scheme, use sqlite: or postgres(ql)://"),
        ("host=db password=Secret: dbname=kc", "failed to open database '<redacted>': unsupported database URL scheme, use sqlite: or postgres(ql)://"),
        ("postgres:kc:Secret@db/kc", "failed to open database 'postgres:<redacted>': PostgreSQL URLs must start with postgres:// or postgresql://"),
        ("postgres://kc:1234#Secret@host/kc", "failed to open database 'postgres:<redacted>': the database URL contains '#', percent-encode it as %23 (e.g. in the password)"),
        ("postgres://kc@db/kc?password=Secret#Wx", "failed to open database 'postgres:<redacted>': the database URL contains '#', percent-encode it as %23 (e.g. in the password)"),
        ("sqlite://kc:Secret@db/kc.db", "failed to open database 'sqlite:<redacted>': error returned from database: (code: 14) unable to open database file. The directory must exist. The database file and the directory holding it must be writable by the user running key-connector (uid 10001 in the Docker image), and the URL needs `?mode=rwc` to create the file on first start"),
    ];
    for (url, expected) in cases {
        let msg = startup_message(url).await;
        assert_eq!(msg, expected, "{url}");
        for secret in ["Secret", "1234", "Wx"] {
            assert!(!msg.contains(secret), "{url}: {msg}");
        }
    }

    // These reach the network, port 1 refuses quickly. Only the URL part of
    // the line is fixed.
    let cases = [
        ("postgres://127.0.0.1:1/kc?user=kc@myserver&password=Secret", "postgres:<redacted>"),
        ("postgres://kc:Secret@127.0.0.1:1/kc?application_name=a@b&password=Secret", "postgres:<redacted>"),
        ("postgres://127.0.0.1:1/kc?user=u&password=a@Secret", "postgres:<redacted>"),
        ("postgres://kc@127.0.0.1:1/kc?password=Sec&Secret", "postgres://kc@127.0.0.1:1/kc"),
        ("postgres://kc@127.0.0.1:1/kc?sslpassword=Secret", "postgres://kc@127.0.0.1:1/kc"),
        ("postgres://kc@127.0.0.1:1/kc?options=-c%20password%3DSecret", "postgres://kc@127.0.0.1:1/kc"),
        ("postgresql://kc:Secret@127.0.0.1:1/kc?sslmode=prefer&password=Secret", "postgresql://kc:***@127.0.0.1:1/kc?sslmode=prefer"),
    ];
    for (url, shown) in cases {
        let msg = startup_message(url).await;
        assert!(msg.starts_with(&format!("failed to open database '{shown}': ")), "{url}: {msg}");
        assert!(!msg.contains("Sec"), "{url}: {msg}");
    }
}

#[test]
fn database_password_is_redacted() {
    let cases = [
        ("postgresql://kc:s3cret@db:5432/kc?sslmode=require", "postgresql://kc:***@db:5432/kc?sslmode=require"),
        ("postgres://db/kc?user=kc&password=s3cret&sslmode=verify-full", "postgres://db/kc?sslmode=verify-full"),
        ("postgres://db/kc?pass%77ord=s3cret", "postgres://db/kc"),
        ("postgres://db/kc?sslmode=s3cret", "postgres://db/kc"),
        ("postgres://db/kc?user=kc@myserver&password=Hunter2", "postgres:<redacted>"),
        ("postgres://kc:pw@db/kc?application_name=a@b&password=Hunter2", "postgres:<redacted>"),
        ("postgres://db/kc?user=u&password=a@b", "postgres:<redacted>"),
        ("postgres://db/kc?password=sec&ret", "postgres://db/kc"),
        // Unencoded '@', '/', '?' or '#' in the password.
        ("postgres://kc:a@b/c#d@db/kc", "postgres:<redacted>"),
        ("postgres://kc:a@b@db/kc", "postgres:<redacted>"),
        ("postgres://kc:1/s3cret@db/kc", "postgres:<redacted>"),
        ("postgres://kc:12?s3cret@db/kc", "postgres:<redacted>"),
        ("postgres://kc:1/s3/cret@db/kc", "postgres:<redacted>"),
        // Nothing secret.
        ("postgres://kc@db/kc", "postgres://kc@db/kc"),
        ("postgres://[::1]:5433/kc", "postgres://[::1]:5433/kc"),
        ("sqlite://keyconnector.db?mode=rwc", "sqlite://keyconnector.db?mode=rwc"),
        ("sqlite::memory:", "sqlite::memory:"),
        ("sqlite://kc:s3cret@db/kc.db", "sqlite:<redacted>"),
    ];
    for (url, expected) in cases {
        assert_eq!(redact_url(url), expected, "{url}");
    }
}

#[test]
fn config_debug_hides_secrets() {
    let cfg = Config {
        bind_addr: "127.0.0.1:0".into(),
        database_url: "postgres://kc:s3cret@db/kc".into(),
        jwt_issuer: None,
        public_key: PublicKeySource::Authority("https://vault.example.com/identity".into()),
        encryption_key: vec![0x42; 32],
        cors_allowed_origins: vec![],
    };
    let debug = format!("{cfg:?}");
    assert!(!debug.contains("s3cret"), "{debug}");
    assert!(!debug.contains("66"), "{debug}");
    assert!(debug.contains("postgres://kc:***@db/kc"), "{debug}");
}

#[test]
fn empty_database_url_means_default() {
    let default = "sqlite://keyconnector.db?mode=rwc";
    assert_eq!(crate::config::database_url_or_default(None), default);
    assert_eq!(crate::config::database_url_or_default(Some(String::new())), default);
    assert_eq!(crate::config::database_url_or_default(Some("sqlite:x.db".into())), "sqlite:x.db");
}

#[tokio::test]
async fn sqlite_store_roundtrips_and_persists() {
    let db_path = temp_path("roundtrip.db");
    let url = format!("sqlite://{}?mode=rwc", db_path.display());

    let store = KeyStore::connect(&url, test_cipher()).await.unwrap();
    assert_eq!(store.get("user-1").await.unwrap(), None);
    store.set("user-1", "first").await.unwrap();
    store.set("user-1", "second").await.unwrap();
    store.set("user-2", "other").await.unwrap();
    assert_eq!(store.get("user-1").await.unwrap().unwrap(), "second");
    drop(store);

    // Reopening the file gives back the same keys, and the startup write
    // check left nothing behind.
    let store = KeyStore::connect(&url, test_cipher()).await.unwrap();
    assert_eq!(store.get("user-1").await.unwrap().unwrap(), "second");
    assert_eq!(store.get("user-2").await.unwrap().unwrap(), "other");
    let pool = sqlx::sqlite::SqlitePoolOptions::new().connect(&url).await.unwrap();
    let (tables,): (i64,) = sqlx::query_as("SELECT count(*) FROM sqlite_master WHERE type = 'table'")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(tables, 1);
    pool.close().await;

    let _ = std::fs::remove_file(&db_path);
}

#[tokio::test]
async fn sqlite_cantopen_explains_the_fix() {
    let dir = temp_path("missing-dir");
    let url = format!("sqlite://{}/keyconnector.db?mode=rwc", dir.display());

    let err = KeyStore::connect(&url, test_cipher()).await.err().unwrap().to_string();
    assert!(err.contains("(code: 14)"), "{err}");
    assert!(err.contains("writable"), "{err}");
    assert!(err.contains("uid 10001"), "{err}");
    assert!(err.contains("mode=rwc"), "{err}");
}

// True when permission bits are enforced for this process (not root).
fn permissions_enforced(dir: &std::path::Path) -> bool {
    std::fs::write(dir.join("probe"), b"").is_err()
}

#[tokio::test]
async fn read_only_sqlite_fails_at_startup() {
    use std::os::unix::fs::PermissionsExt;

    for read_only_dir in [false, true] {
        let dir = temp_path("readonly");
        std::fs::create_dir_all(&dir).unwrap();
        let db_path = dir.join("kc.db");
        let url = format!("sqlite://{}?mode=rwc", db_path.display());

        let store = KeyStore::connect(&url, test_cipher()).await.unwrap();
        store.set("user-1", "kept").await.unwrap();
        drop(store);
        let before = std::fs::read(&db_path).unwrap();

        let target = if read_only_dir { &dir } else { &db_path };
        let mode = if read_only_dir { 0o555 } else { 0o444 };
        std::fs::set_permissions(target, std::fs::Permissions::from_mode(mode)).unwrap();
        if read_only_dir && !permissions_enforced(&dir) {
            eprintln!("running as root, skipping the read-only check");
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
            let _ = std::fs::remove_dir_all(&dir);
            return;
        }

        let result = KeyStore::connect(&url, test_cipher()).await;
        std::fs::set_permissions(target, std::fs::Permissions::from_mode(0o755)).unwrap();
        let err = result.err().expect("read-only database must fail at startup").to_string();
        assert!(err.contains("writable"), "{err}");
        assert!(err.contains("uid 10001"), "{err}");

        // The check did not change the file.
        assert_eq!(std::fs::read(&db_path).unwrap(), before);
        let store = KeyStore::connect(&url, test_cipher()).await.unwrap();
        assert_eq!(store.get("user-1").await.unwrap().unwrap(), "kept");

        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[test]
fn postgres_requests_fail_fast_when_the_database_hangs() {
    let timeout = crate::store::pg_pool_options().get_acquire_timeout();
    assert!(timeout <= std::time::Duration::from_secs(5), "{timeout:?}");
}

#[tokio::test]
async fn unreachable_postgres_reports_the_cause() {
    let started = std::time::Instant::now();
    let msg = startup_message("postgres://kc:Secret@127.0.0.1:1/kc").await;
    assert!(started.elapsed() < std::time::Duration::from_secs(5), "{msg}");
    assert!(msg.to_lowercase().contains("refused"), "{msg}");
    assert!(msg.contains("postgres://kc:***@127.0.0.1:1/kc"), "{msg}");
    assert!(!msg.contains("Secret"), "{msg}");
}

// Another instance stores a new key between the sealing pass reading a
// plaintext row and writing it back. The new key must survive.
async fn check_sealing_keeps_newer_keys(url: &str) {
    let store = KeyStore::connect(url, test_cipher()).await.unwrap();
    let snapshot = vec![("race-user".to_string(), "old-plaintext".to_string())];
    store.set("race-user", "new-key").await.unwrap();
    store.seal_rows(snapshot).await.unwrap();
    assert_eq!(store.get("race-user").await.unwrap().unwrap(), "new-key");
}

#[tokio::test]
async fn sealing_does_not_overwrite_newer_keys_sqlite() {
    let db_path = temp_path("seal-race.db");
    check_sealing_keeps_newer_keys(&format!("sqlite://{}?mode=rwc", db_path.display())).await;
    let _ = std::fs::remove_file(&db_path);
}

// Creates a fresh database on the server KC_TEST_POSTGRES_URL points at and
// returns its name and URL, or None when the variable is unset. The test job
// in .github/workflows/build.yml sets it.
async fn pg_test_db() -> Option<(String, String)> {
    let Ok(admin_url) = std::env::var("KC_TEST_POSTGRES_URL") else {
        eprintln!("KC_TEST_POSTGRES_URL not set, skipping");
        return None;
    };
    let name = temp_path("pg").file_name().unwrap().to_str().unwrap().replace('-', "_");
    let mut admin = sqlx::postgres::PgConnection::connect(&admin_url).await.unwrap();
    sqlx::query(&format!("CREATE DATABASE {name}")).execute(&mut admin).await.unwrap();
    let mut url = url::Url::parse(&admin_url).unwrap();
    url.set_path(&format!("/{name}"));
    Some((name, url.to_string()))
}

async fn pg_drop_db(name: &str) {
    let admin_url = std::env::var("KC_TEST_POSTGRES_URL").unwrap();
    let mut admin = sqlx::postgres::PgConnection::connect(&admin_url).await.unwrap();
    sqlx::query(&format!("DROP DATABASE {name} WITH (FORCE)")).execute(&mut admin).await.unwrap();
}

use sqlx::Connection as _;

// Runs only when KC_TEST_POSTGRES_URL points at a server where the user may
// create databases, e.g. postgres://postgres:pw@localhost:5432/postgres
#[tokio::test]
async fn postgres_store_roundtrips() {
    let Some((name, url)) = pg_test_db().await else { return };

    let store = KeyStore::connect(&url, test_cipher()).await.unwrap();
    assert_eq!(store.get("user-1").await.unwrap(), None);
    store.set("user-1", "first").await.unwrap();
    store.set("user-1", "second").await.unwrap();
    assert_eq!(store.get("user-1").await.unwrap().unwrap(), "second");

    // A second connect runs the schema setup and the sealing pass again.
    let store = KeyStore::connect(&url, test_cipher()).await.unwrap();
    assert_eq!(store.get("user-1").await.unwrap().unwrap(), "second");

    pg_drop_db(&name).await;
}

#[tokio::test]
async fn postgres_plaintext_rows_are_sealed_on_startup() {
    let Some((name, url)) = pg_test_db().await else { return };

    let mut conn = sqlx::postgres::PgConnection::connect(&url).await.unwrap();
    sqlx::query("CREATE TABLE user_keys (user_id TEXT PRIMARY KEY NOT NULL, key TEXT NOT NULL)")
        .execute(&mut conn)
        .await
        .unwrap();
    sqlx::query("INSERT INTO user_keys VALUES ('legacy-user', 'legacy-plaintext-key')")
        .execute(&mut conn)
        .await
        .unwrap();

    let store = KeyStore::connect(&url, test_cipher()).await.unwrap();
    assert_eq!(store.get("legacy-user").await.unwrap().unwrap(), "legacy-plaintext-key");
    let (stored,): (String,) = sqlx::query_as("SELECT key FROM user_keys WHERE user_id = 'legacy-user'")
        .fetch_one(&mut conn)
        .await
        .unwrap();
    assert!(KeyCipher::is_sealed(&stored));
    conn.close().await.unwrap();

    pg_drop_db(&name).await;
}

#[tokio::test]
async fn sealing_does_not_overwrite_newer_keys_postgres() {
    let Some((name, url)) = pg_test_db().await else { return };
    check_sealing_keeps_newer_keys(&url).await;
    pg_drop_db(&name).await;
}

// Several instances starting at once against an empty database.
#[tokio::test]
async fn postgres_concurrent_connects_create_the_schema_once() {
    let Some((name, url)) = pg_test_db().await else { return };

    let mut conn = sqlx::postgres::PgConnection::connect(&url).await.unwrap();
    for _ in 0..10 {
        sqlx::query("DROP TABLE IF EXISTS user_keys").execute(&mut conn).await.unwrap();
        let tasks: Vec<_> = (0..6)
            .map(|_| {
                let url = url.clone();
                tokio::spawn(async move { KeyStore::connect(&url, test_cipher()).await.map(|_| ()) })
            })
            .collect();
        for task in tasks {
            if let Err(e) = task.await.unwrap() {
                panic!("concurrent connect failed: {e}");
            }
        }
    }
    conn.close().await.unwrap();

    pg_drop_db(&name).await;
}

// A role without CREATE on the schema (the PostgreSQL 15+ default for
// `public`) can start once the table exists.
#[tokio::test]
async fn postgres_starts_without_create_privilege() {
    let Some((name, url)) = pg_test_db().await else { return };
    let role = format!("{name}_app");

    let mut conn = sqlx::postgres::PgConnection::connect(&url).await.unwrap();
    for stmt in [
        "CREATE TABLE user_keys (user_id TEXT PRIMARY KEY NOT NULL, key TEXT NOT NULL)".to_string(),
        "INSERT INTO user_keys VALUES ('legacy-user', 'legacy-plaintext-key')".to_string(),
        format!("CREATE ROLE {role} LOGIN PASSWORD 'pw'"),
        format!("REVOKE CREATE ON SCHEMA public FROM PUBLIC, {role}"),
        format!("GRANT SELECT, INSERT, UPDATE ON user_keys TO {role}"),
    ] {
        sqlx::query(&stmt).execute(&mut conn).await.unwrap();
    }
    conn.close().await.unwrap();

    let mut app_url = url::Url::parse(&url).unwrap();
    app_url.set_username(&role).unwrap();
    app_url.set_password(Some("pw")).unwrap();
    let app_url = app_url.to_string();

    let store = KeyStore::connect(&app_url, test_cipher()).await.unwrap();
    assert_eq!(store.get("legacy-user").await.unwrap().unwrap(), "legacy-plaintext-key");
    store.set("user-1", "k").await.unwrap();
    assert_eq!(store.get("user-1").await.unwrap().unwrap(), "k");
    drop(store);

    pg_drop_db(&name).await;
    let admin_url = std::env::var("KC_TEST_POSTGRES_URL").unwrap();
    let mut admin = sqlx::postgres::PgConnection::connect(&admin_url).await.unwrap();
    sqlx::query(&format!("DROP ROLE {role}")).execute(&mut admin).await.unwrap();
}
