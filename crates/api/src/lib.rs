//! axum REST API. Routes mirror octo's non-custodial flow, plus the
//! policy-engine check and audit-log write that are new to Kobo.
//!
//! An OpenAPI document is served at `/v1/openapi.json` (static for now —
//! wiring `utoipa` to generate it from these handlers is a good
//! "medium"-complexity contributor issue, see CONTRIBUTING.md).

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::sync::Mutex;

use kobo_audit::AuditLog;
use kobo_policy::{CustomerLedger, PolicyDecision, VelocityLimit};
use kobo_store::{DepositAddress, Store, Wallet};
use kobo_wallet_core::encode_muxed_account;

pub struct AppState {
    pub store: Arc<dyn Store>,
    pub audit: Mutex<AuditLog>,
    pub default_limit: VelocityLimit,
    // wallet_id -> per-customer ledger; a real deployment keys this by
    // (wallet_id, customer_id) in Postgres instead of in memory.
    pub ledgers: Mutex<std::collections::HashMap<String, CustomerLedger>>,
}

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/v1/wallets", post(create_wallet))
        .route("/v1/wallets/:id/addresses", post(create_address))
        .route("/v1/wallets/:id/submit-signed", post(submit_signed))
        .route("/v1/openapi.json", get(openapi_stub))
        .with_state(state)
}

#[derive(Deserialize)]
struct CreateWalletRequest {
    public_key: String,
    label: String,
    org_id: String,
}

async fn create_wallet(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateWalletRequest>,
) -> impl IntoResponse {
    let wallet = Wallet {
        id: format!("w_{}", uuid_like()),
        org_id: req.org_id,
        label: req.label,
        public_key: req.public_key,
        next_customer_id: 0,
    };
    let created = state.store.create_wallet(wallet).await;
    (StatusCode::CREATED, Json(created))
}

#[derive(Serialize)]
struct AddressResponse {
    muxed_address: String,
    fallback_account: String,
    fallback_memo_id: u64,
}

async fn create_address(
    State(state): State<Arc<AppState>>,
    Path(wallet_id): Path<String>,
) -> impl IntoResponse {
    let Some(wallet) = state.store.get_wallet(&wallet_id).await else {
        return (StatusCode::NOT_FOUND, "wallet not found").into_response();
    };
    let Some(customer_id) = state.store.allocate_next_customer_id(&wallet_id).await else {
        return (StatusCode::NOT_FOUND, "wallet not found").into_response();
    };

    let Ok(pk_bytes): Result<[u8; 32], _> = decode_pubkey_placeholder(&wallet.public_key) else {
        return (StatusCode::INTERNAL_SERVER_ERROR, "wallet has an invalid public key").into_response();
    };

    let muxed = encode_muxed_account(&pk_bytes, customer_id);
    state
        .store
        .save_deposit_address(DepositAddress {
            wallet_id: wallet_id.clone(),
            customer_id,
            muxed_address: muxed.clone(),
        })
        .await;

    Json(AddressResponse {
        muxed_address: muxed,
        fallback_account: wallet.public_key,
        fallback_memo_id: customer_id,
    })
    .into_response()
}

#[derive(Deserialize)]
struct SubmitSignedRequest {
    transaction_xdr: String,
    customer_id: u64,
    amount_stroops: i128,
}

async fn submit_signed(
    State(state): State<Arc<AppState>>,
    Path(wallet_id): Path<String>,
    headers: HeaderMap,
    Json(req): Json<SubmitSignedRequest>,
) -> impl IntoResponse {
    // Idempotency-Key handling (new vs. octo): a real implementation looks
    // this up in kobo-store and short-circuits with the prior result on a
    // repeat. Left as a contributor issue — see CONTRIBUTING.md.
    let _idempotency_key = headers.get("Idempotency-Key");

    let now = now_unix();
    let mut ledgers = state.ledgers.lock().unwrap();
    let ledger = ledgers.entry(format!("{wallet_id}:{}", req.customer_id)).or_default();

    let decision = ledger.evaluate(state.default_limit, now, req.amount_stroops);
    let mut audit = state.audit.lock().unwrap();

    match decision {
        PolicyDecision::Deny { attempted_total, limit } => {
            audit.append(
                now,
                &wallet_id,
                "policy_denied",
                &format!("customer={} attempted_total={attempted_total} limit={limit}", req.customer_id),
            );
            (StatusCode::FORBIDDEN, "velocity limit exceeded").into_response()
        }
        PolicyDecision::Allow => {
            ledger.record(now, req.amount_stroops);
            audit.append(
                now,
                &wallet_id,
                "submit_signed_allowed",
                &format!("customer={} amount={} xdr_len={}", req.customer_id, req.amount_stroops, req.transaction_xdr.len()),
            );
            // Real relay-to-Horizon call goes here — left as a contributor
            // issue (validate envelope via kobo-wallet-core, then POST to
            // Horizon/Soroban RPC).
            StatusCode::ACCEPTED.into_response()
        }
    }
}

async fn openapi_stub() -> impl IntoResponse {
    Json(serde_json::json!({
        "openapi": "3.0.0",
        "info": { "title": "Kobo API", "version": "0.1.0" },
        "paths": {}
    }))
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn uuid_like() -> String {
    format!("{:x}", now_unix() as u128 * 2654435761u128 % u128::from(u64::MAX))
}

/// Placeholder until wallet public keys are stored/decoded via
/// `kobo_wallet_core::decode_account_id`. Kept separate so the happy-path
/// wiring above is easy to follow.
fn decode_pubkey_placeholder(public_key: &str) -> Result<[u8; 32], ()> {
    kobo_wallet_core::decode_account_id(public_key).map_err(|_| ())
}
