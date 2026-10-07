//! SEP-0005-style hardened key derivation (SLIP-0010 for ed25519).
//!
//! This crate never derives *customer* keys — customers hold their own keys
//! client-side. It exists only so the server can derive a wallet's optional
//! gas-tank fee keypair deterministically from a seed, instead of storing a
//! raw keypair with no recovery path.

use ed25519_dalek::SigningKey;
use hmac::{Hmac, Mac};
use sha2::Sha512;
use zeroize::Zeroizing;

type HmacSha512 = Hmac<Sha512>;

const ED25519_SEED_KEY: &[u8] = b"ed25519 seed";

/// Master key + chain code, per SLIP-0010.
struct ExtendedKey {
    key: Zeroizing<[u8; 32]>,
    chain_code: [u8; 32],
}

fn master_key(seed: &[u8]) -> ExtendedKey {
    let mut mac = HmacSha512::new_from_slice(ED25519_SEED_KEY).expect("hmac accepts any key length");
    mac.update(seed);
    let result = mac.finalize().into_bytes();
    let mut key = [0u8; 32];
    let mut chain_code = [0u8; 32];
    key.copy_from_slice(&result[..32]);
    chain_code.copy_from_slice(&result[32..]);
    ExtendedKey { key: Zeroizing::new(key), chain_code }
}

/// SLIP-0010 ed25519 only supports hardened derivation, so every index is
/// forced into the hardened range regardless of what's passed in.
fn derive_hardened_child(parent: &ExtendedKey, index: u32) -> ExtendedKey {
    let hardened_index = index | 0x8000_0000;
    let mut mac = HmacSha512::new_from_slice(&parent.chain_code).expect("hmac accepts any key length");
    mac.update(&[0u8]);
    mac.update(parent.key.as_slice());
    mac.update(&hardened_index.to_be_bytes());
    let result = mac.finalize().into_bytes();
    let mut key = [0u8; 32];
    let mut chain_code = [0u8; 32];
    key.copy_from_slice(&result[..32]);
    chain_code.copy_from_slice(&result[32..]);
    ExtendedKey { key: Zeroizing::new(key), chain_code }
}

/// Derive an ed25519 signing key at `m/44'/148'/{account_index}'`
/// (SEP-0005's Stellar path). `seed` is typically a BIP-39 seed the operator
/// generated once and stored in a KMS — never in this codebase.
pub fn derive_stellar_signing_key(seed: &[u8], account_index: u32) -> SigningKey {
    let m = master_key(seed);
    let purpose = derive_hardened_child(&m, 44);
    let coin_type = derive_hardened_child(&purpose, 148);
    let account = derive_hardened_child(&coin_type, account_index);
    SigningKey::from_bytes(&account.key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derivation_is_deterministic() {
        let seed = b"kobo-test-seed-not-for-real-funds";
        let a = derive_stellar_signing_key(seed, 0);
        let b = derive_stellar_signing_key(seed, 0);
        assert_eq!(a.to_bytes(), b.to_bytes());
    }

    #[test]
    fn different_account_indices_yield_different_keys() {
        let seed = b"kobo-test-seed-not-for-real-funds";
        let a = derive_stellar_signing_key(seed, 0);
        let b = derive_stellar_signing_key(seed, 1);
        assert_ne!(a.to_bytes(), b.to_bytes());
    }
}
