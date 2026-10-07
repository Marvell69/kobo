//! AES-256-GCM seal/open for secrets that must live at rest on the server —
//! today, only a wallet's optional gas-tank fee key. Customer keys never
//! pass through this crate; they never reach the server at all.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use rand::RngCore;
use thiserror::Error;
use zeroize::Zeroizing;

pub const NONCE_LEN: usize = 12;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("master key must be exactly 32 bytes")]
    BadKeyLength,
    #[error("ciphertext is shorter than the nonce")]
    Truncated,
    #[error("seal failed")]
    SealFailed,
    #[error("open failed (wrong key, wrong AAD/network, or tampered ciphertext)")]
    OpenFailed,
}

/// Seal `plaintext` under `master_key` (must be 32 bytes), binding `aad`
/// (e.g. the network passphrase) so a testnet-sealed secret can never be
/// opened as mainnet and vice versa. Returns `nonce || ciphertext`.
pub fn seal(master_key: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let key = Key::<Aes256Gcm>::from_slice(
        master_key.get(..32).ok_or(CryptoError::BadKeyLength)?,
    );
    let cipher = Aes256Gcm::new(key);

    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, Payload { msg: plaintext, aad })
        .map_err(|_| CryptoError::SealFailed)?;

    let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Open a blob produced by [`seal`]. The returned plaintext is wrapped in
/// `Zeroizing` so it is wiped from memory as soon as it goes out of scope.
pub fn open(
    master_key: &[u8],
    aad: &[u8],
    sealed: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let key = Key::<Aes256Gcm>::from_slice(
        master_key.get(..32).ok_or(CryptoError::BadKeyLength)?,
    );
    let cipher = Aes256Gcm::new(key);

    if sealed.len() < NONCE_LEN {
        return Err(CryptoError::Truncated);
    }
    let (nonce_bytes, ciphertext) = sealed.split_at(NONCE_LEN);
    let nonce = Nonce::from_slice(nonce_bytes);

    let plaintext = cipher
        .decrypt(nonce, Payload { msg: ciphertext, aad })
        .map_err(|_| CryptoError::OpenFailed)?;

    Ok(Zeroizing::new(plaintext))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key32() -> [u8; 32] {
        let mut k = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut k);
        k
    }

    #[test]
    fn round_trip() {
        let key = key32();
        let aad = b"Test SDF Network ; September 2015";
        let secret = b"S-SEED-GOES-HERE-DO-NOT-LOG";

        let sealed = seal(&key, aad, secret).unwrap();
        assert_ne!(sealed.as_slice(), secret.as_slice());

        let opened = open(&key, aad, &sealed).unwrap();
        assert_eq!(opened.as_slice(), secret.as_slice());
    }

    #[test]
    fn wrong_network_aad_fails() {
        let key = key32();
        let sealed = seal(&key, b"Test SDF Network ; September 2015", b"secret").unwrap();
        let result = open(&key, b"Public Global Stellar Network ; September 2015", &sealed);
        assert!(result.is_err());
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let key = key32();
        let mut sealed = seal(&key, b"aad", b"secret").unwrap();
        let last = sealed.len() - 1;
        sealed[last] ^= 0xFF;
        assert!(open(&key, b"aad", &sealed).is_err());
    }

    #[test]
    fn wrong_key_length_rejected() {
        let short_key = [0u8; 16];
        assert!(matches!(
            seal(&short_key, b"aad", b"secret"),
            Err(CryptoError::BadKeyLength)
        ));
    }
}
