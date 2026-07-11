// End to end tests against the real router, with real RS256 signed tokens.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use jsonwebtoken::{encode, EncodingKey, Header};
use serde::Serialize;
use tower::ServiceExt; // for `oneshot`

use crate::config::{Config, PublicKeySource};
use crate::jwt::TokenVerifier;
use crate::routes::{router, AppState};
use crate::store::KeyStore;

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
        jwt_issuer: ISSUER.into(),
        public_key: PublicKeySource::Inline(pub_pem()),
        cors_allowed_origins: vec![],
    };
    let verifier = TokenVerifier::from_config(&cfg).unwrap();
    let store = KeyStore::connect(&cfg.database_url).await.unwrap();
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
