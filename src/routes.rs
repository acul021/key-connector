use axum::extract::State;
use axum::http::{header, HeaderMap, HeaderName, Method};
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use tower_http::cors::{AllowOrigin, CorsLayer};

use crate::error::ApiError;
use crate::jwt::{bearer_from_header, TokenVerifier};
use crate::store::KeyStore;

#[derive(Clone)]
pub struct AppState {
    pub verifier: TokenVerifier,
    pub store: KeyStore,
}

#[derive(Serialize)]
struct UserKeyResponse {
    key: String,
}

#[derive(Deserialize)]
struct UserKeyRequest {
    key: String,
}

pub fn router(state: AppState, allowed_origins: &[String]) -> Router {
    Router::new()
        .route("/alive", get(alive))
        .route("/user-keys", get(get_user_keys).post(post_user_keys))
        .layer(cors(allowed_origins))
        .with_state(state)
}

// The web vault runs on a different origin than the connector, so the clients
// need CORS to reach /user-keys. Auth is a bearer token, so an empty allow list
// just mirrors the request origin.
fn cors(allowed_origins: &[String]) -> CorsLayer {
    let origin = if allowed_origins.is_empty() {
        AllowOrigin::mirror_request()
    } else {
        AllowOrigin::list(allowed_origins.iter().filter_map(|o| o.parse().ok()))
    };
    CorsLayer::new()
        .allow_origin(origin)
        .allow_methods([Method::GET, Method::POST])
        .allow_headers([
            header::AUTHORIZATION,
            header::CONTENT_TYPE,
            header::ACCEPT,
            // The clients send these on every request via an interceptor.
            HeaderName::from_static("bitwarden-client-name"),
            HeaderName::from_static("bitwarden-client-version"),
        ])
}

async fn alive() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "status": "ok" }))
}

fn authenticate(state: &AppState, headers: &HeaderMap) -> Result<String, ApiError> {
    let header = headers.get(axum::http::header::AUTHORIZATION).and_then(|v| v.to_str().ok());
    let token = bearer_from_header(header)?;
    Ok(state.verifier.verify(token)?.sub)
}

async fn get_user_keys(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<UserKeyResponse>, ApiError> {
    let user_id = authenticate(&state, &headers)?;
    match state.store.get(&user_id).await {
        Ok(Some(key)) => Ok(Json(UserKeyResponse { key })),
        Ok(None) => Err(ApiError::KeyNotFound),
        Err(e) => {
            tracing::error!(error = %e, "failed to read user key");
            Err(ApiError::Internal)
        }
    }
}

async fn post_user_keys(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<UserKeyRequest>,
) -> Result<(), ApiError> {
    let user_id = authenticate(&state, &headers)?;
    state.store.set(&user_id, &body.key).await.map_err(|e| {
        tracing::error!(error = %e, "failed to store user key");
        ApiError::Internal
    })?;
    Ok(())
}
