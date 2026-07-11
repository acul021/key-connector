mod config;
mod error;
mod jwt;
mod routes;
mod store;

#[cfg(test)]
mod tests;

use config::Config;
use jwt::TokenVerifier;
use routes::AppState;
use store::KeyStore;
use tower_http::trace::TraceLayer;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "key_connector=info,tower_http=info".into()),
        )
        .init();

    if let Err(e) = run().await {
        tracing::error!("fatal: {e}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), String> {
    let cfg = Config::from_env()?;
    tracing::info!(bind = %cfg.bind_addr, issuer = %cfg.jwt_issuer, "starting key-connector");

    let verifier = TokenVerifier::from_config(&cfg)?;
    let store = KeyStore::connect(&cfg.database_url)
        .await
        .map_err(|e| format!("failed to open database '{}': {e}", cfg.database_url))?;

    let app = routes::router(AppState { verifier, store }).layer(TraceLayer::new_for_http());

    let listener = tokio::net::TcpListener::bind(&cfg.bind_addr)
        .await
        .map_err(|e| format!("failed to bind {}: {e}", cfg.bind_addr))?;

    tracing::info!("listening on {}", cfg.bind_addr);
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .map_err(|e| format!("server error: {e}"))
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
    tracing::info!("shutting down");
}
