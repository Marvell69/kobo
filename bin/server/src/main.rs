use kobo_api::AppState;
use kobo_audit::AuditLog;
use kobo_policy::VelocityLimit;
use kobo_store::InMemoryStore;
use std::sync::{Arc, Mutex};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let bind_addr = std::env::var("BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".to_string());
    let default_cap: i128 = std::env::var("DEFAULT_DAILY_WITHDRAWAL_CAP_STROOPS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);

    let state = Arc::new(AppState {
        store: Arc::new(InMemoryStore::new()),
        audit: Mutex::new(AuditLog::new()),
        default_limit: VelocityLimit {
            window_seconds: 86_400,
            max_amount_stroops: default_cap,
        },
        ledgers: Mutex::new(std::collections::HashMap::new()),
    });

    let app = kobo_api::router(state);

    tracing::info!("kobo-server listening on {bind_addr}");
    let listener = tokio::net::TcpListener::bind(&bind_addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
