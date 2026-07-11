use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("missing or malformed Authorization header")]
    MissingToken,
    #[error("invalid access token: {0}")]
    InvalidToken(String),
    #[error("no key stored for this user")]
    KeyNotFound,
    #[error("internal error")]
    Internal,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = match self {
            ApiError::MissingToken | ApiError::InvalidToken(_) => StatusCode::UNAUTHORIZED,
            ApiError::KeyNotFound => StatusCode::NOT_FOUND,
            ApiError::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        };
        // the clients expect a JSON object body
        let body = Json(json!({ "message": self.to_string() }));
        (status, body).into_response()
    }
}
