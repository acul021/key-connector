use axum::extract::State;
use axum::http::HeaderMap;
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

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

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/alive", get(alive))
        .route("/user-keys", get(get_user_keys).post(post_user_keys))
        .with_state(state)
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
