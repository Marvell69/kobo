//! Storage trait + an in-memory reference implementation. Swap in a
//! Postgres/sqlx implementation behind this same trait for production —
//! keeping the trait boundary here means `kobo-api` never needs a live DB
//! just to compile or unit-test.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Wallet {
    pub id: String,
    pub org_id: String,
    pub label: String,
    pub public_key: String, // G... — the one on-chain master account
    pub next_customer_id: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DepositAddress {
    pub wallet_id: String,
    pub customer_id: u64,
    pub muxed_address: String, // M...
}

#[async_trait]
pub trait Store: Send + Sync {
    async fn create_wallet(&self, wallet: Wallet) -> Wallet;
    async fn get_wallet(&self, id: &str) -> Option<Wallet>;
    async fn allocate_next_customer_id(&self, wallet_id: &str) -> Option<u64>;
    async fn save_deposit_address(&self, addr: DepositAddress);
}

#[derive(Default)]
pub struct InMemoryStore {
    wallets: Mutex<HashMap<String, Wallet>>,
    addresses: Mutex<Vec<DepositAddress>>,
}

impl InMemoryStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl Store for InMemoryStore {
    async fn create_wallet(&self, wallet: Wallet) -> Wallet {
        self.wallets
            .lock()
            .unwrap()
            .insert(wallet.id.clone(), wallet.clone());
        wallet
    }

    async fn get_wallet(&self, id: &str) -> Option<Wallet> {
        self.wallets.lock().unwrap().get(id).cloned()
    }

    async fn allocate_next_customer_id(&self, wallet_id: &str) -> Option<u64> {
        let mut wallets = self.wallets.lock().unwrap();
        let wallet = wallets.get_mut(wallet_id)?;
        let id = wallet.next_customer_id;
        wallet.next_customer_id += 1;
        Some(id)
    }

    async fn save_deposit_address(&self, addr: DepositAddress) {
        self.addresses.lock().unwrap().push(addr);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn customer_ids_increment_per_wallet() {
        let store = InMemoryStore::new();
        store
            .create_wallet(Wallet {
                id: "w1".into(),
                org_id: "org1".into(),
                label: "acme".into(),
                public_key: "GABC...".into(),
                next_customer_id: 0,
            })
            .await;

        let first = store.allocate_next_customer_id("w1").await.unwrap();
        let second = store.allocate_next_customer_id("w1").await.unwrap();
        assert_eq!(first, 0);
        assert_eq!(second, 1);
    }
}
