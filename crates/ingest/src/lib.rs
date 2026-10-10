//! Horizon (and, new vs. octo, Soroban SEP-41 token) deposit ingest.
//!
//! This crate defines the trait boundary and cursor logic; the real Horizon
//! SSE client and Soroban RPC event listener are left as an integration
//! task (see CONTRIBUTING.md — both are good "medium" complexity issues).

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Asset {
    Native,
    Classic { code: String, issuer: String },
    SorobanToken { contract_id: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DepositEvent {
    pub tx_hash: String,
    pub op_index: u32,
    pub muxed_destination: String,
    pub asset: Asset,
    pub amount_stroops: i128,
    pub successful: bool,
}

/// A durable cursor lets ingest resume exactly where it left off after a
/// restart instead of re-scanning history or missing a gap.
#[async_trait]
pub trait CursorStore: Send + Sync {
    async fn load_cursor(&self, stream_id: &str) -> Option<String>;
    async fn save_cursor(&self, stream_id: &str, cursor: String);
}

/// De-duplicates deposit events on `(tx_hash, op_index)` so a reorg replay
/// or an at-least-once delivery guarantee never double-credits a customer.
#[derive(Default)]
pub struct DeduplicatingIngestor {
    seen: std::collections::HashSet<(String, u32)>,
}

impl DeduplicatingIngestor {
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns `true` if this event should be credited (first time seen and
    /// marked successful), `false` if it should be skipped.
    pub fn should_credit(&mut self, event: &DepositEvent) -> bool {
        if !event.successful {
            return false;
        }
        let key = (event.tx_hash.clone(), event.op_index);
        if self.seen.contains(&key) {
            return false;
        }
        self.seen.insert(key);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_event(tx_hash: &str, op_index: u32, successful: bool) -> DepositEvent {
        DepositEvent {
            tx_hash: tx_hash.into(),
            op_index,
            muxed_destination: "MABC...".into(),
            asset: Asset::Native,
            amount_stroops: 10_000_000,
            successful,
        }
    }

    #[test]
    fn credits_a_new_successful_event_once() {
        let mut ingestor = DeduplicatingIngestor::new();
        let event = sample_event("tx1", 0, true);
        assert!(ingestor.should_credit(&event));
        assert!(!ingestor.should_credit(&event), "replay must not double-credit");
    }

    #[test]
    fn ignores_unsuccessful_events() {
        let mut ingestor = DeduplicatingIngestor::new();
        let event = sample_event("tx2", 0, false);
        assert!(!ingestor.should_credit(&event));
    }
}
