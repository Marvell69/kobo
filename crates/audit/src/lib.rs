//! Hash-chained, tamper-evident audit log — new vs. octo.
//!
//! Every relay decision (allowed or denied, and why) is appended here before
//! broadcast. Each entry stores the SHA-256 of the previous entry, so
//! altering or deleting a past row breaks every hash after it — the same
//! tamper-evidence idea as a blockchain, without needing one: this is an
//! append-only Postgres table in production, verified independently by
//! `verify_chain` below (e.g. from a periodic compliance job).

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub sequence: u64,
    pub at_unix: u64,
    pub wallet_id: String,
    pub event: String, // e.g. "submit_signed_allowed", "policy_denied"
    pub detail: String,
    pub prev_hash: String,
    pub hash: String,
}

fn compute_hash(sequence: u64, at_unix: u64, wallet_id: &str, event: &str, detail: &str, prev_hash: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(sequence.to_be_bytes());
    hasher.update(at_unix.to_be_bytes());
    hasher.update(wallet_id.as_bytes());
    hasher.update(event.as_bytes());
    hasher.update(detail.as_bytes());
    hasher.update(prev_hash.as_bytes());
    hex::encode(hasher.finalize())
}

pub const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Default)]
pub struct AuditLog {
    entries: Vec<AuditEntry>,
}

impl AuditLog {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn append(&mut self, at_unix: u64, wallet_id: &str, event: &str, detail: &str) -> AuditEntry {
        let sequence = self.entries.len() as u64;
        let prev_hash = self
            .entries
            .last()
            .map(|e| e.hash.clone())
            .unwrap_or_else(|| GENESIS_HASH.to_string());
        let hash = compute_hash(sequence, at_unix, wallet_id, event, detail, &prev_hash);
        let entry = AuditEntry {
            sequence,
            at_unix,
            wallet_id: wallet_id.to_string(),
            event: event.to_string(),
            detail: detail.to_string(),
            prev_hash,
            hash,
        };
        self.entries.push(entry.clone());
        entry
    }

    pub fn entries(&self) -> &[AuditEntry] {
        &self.entries
    }
}

/// Recompute every hash in the chain and confirm it matches the stored
/// value and links correctly to its predecessor. Returns the index of the
/// first broken entry, if any.
pub fn verify_chain(entries: &[AuditEntry]) -> Result<(), usize> {
    let mut expected_prev = GENESIS_HASH.to_string();
    for (i, entry) in entries.iter().enumerate() {
        if entry.prev_hash != expected_prev {
            return Err(i);
        }
        let recomputed = compute_hash(
            entry.sequence,
            entry.at_unix,
            &entry.wallet_id,
            &entry.event,
            &entry.detail,
            &entry.prev_hash,
        );
        if recomputed != entry.hash {
            return Err(i);
        }
        expected_prev = entry.hash.clone();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_verifies_clean() {
        let mut log = AuditLog::new();
        log.append(1_000, "w1", "submit_signed_allowed", "tx=abc");
        log.append(1_001, "w1", "policy_denied", "cap exceeded");
        assert!(verify_chain(log.entries()).is_ok());
    }

    #[test]
    fn tampering_with_an_entry_breaks_the_chain() {
        let mut log = AuditLog::new();
        log.append(1_000, "w1", "submit_signed_allowed", "tx=abc");
        log.append(1_001, "w1", "policy_denied", "cap exceeded");

        let mut tampered: Vec<AuditEntry> = log.entries().to_vec();
        tampered[0].detail = "tx=forged".to_string(); // hash no longer matches

        assert_eq!(verify_chain(&tampered), Err(0));
    }

    #[test]
    fn deleting_an_entry_breaks_the_chain() {
        let mut log = AuditLog::new();
        log.append(1_000, "w1", "a", "1");
        log.append(1_001, "w1", "b", "2");
        log.append(1_002, "w1", "c", "3");

        let mut tampered: Vec<AuditEntry> = log.entries().to_vec();
        tampered.remove(1); // the link from entry 0 now skips ahead

        assert_eq!(verify_chain(&tampered), Err(1));
    }
}
