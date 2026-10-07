//! Minimal StrKey codec: classic accounts (`G...`) and muxed accounts
//! (`M...`, SEP-0023). Deliberately dependency-light so it's easy to audit.

use thiserror::Error;

const ACCOUNT_VERSION: u8 = 6 << 3; // 0x30
const MUXED_VERSION: u8 = 12 << 3; // 0x60
const ALPHABET: base32::Alphabet = base32::Alphabet::Rfc4648 { padding: false };

#[derive(Debug, Error, PartialEq, Eq)]
pub enum StrKeyError {
    #[error("invalid base32 encoding")]
    InvalidBase32,
    #[error("unexpected version byte")]
    WrongVersion,
    #[error("checksum mismatch — address is corrupted or mistyped")]
    BadChecksum,
    #[error("payload has the wrong length for this key type")]
    BadLength,
}

/// CRC16/XModem: poly 0x1021, init 0x0000, no reflect, no xor-out.
/// This is the checksum algorithm StrKey (SEP-0023 / classic StrKey) uses.
fn crc16_xmodem(data: &[u8]) -> u16 {
    let mut crc: u16 = 0x0000;
    for &byte in data {
        crc ^= (byte as u16) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 {
                (crc << 1) ^ 0x1021
            } else {
                crc << 1
            };
        }
    }
    crc
}

fn encode(version: u8, payload: &[u8]) -> String {
    let mut buf = Vec::with_capacity(1 + payload.len() + 2);
    buf.push(version);
    buf.extend_from_slice(payload);
    let checksum = crc16_xmodem(&buf);
    buf.push((checksum & 0xFF) as u8); // little-endian
    buf.push((checksum >> 8) as u8);
    base32::encode(ALPHABET, &buf)
}

fn decode(expected_version: u8, s: &str) -> Result<Vec<u8>, StrKeyError> {
    let raw = base32::decode(ALPHABET, s).ok_or(StrKeyError::InvalidBase32)?;
    if raw.len() < 3 {
        return Err(StrKeyError::BadLength);
    }
    let (body, checksum_bytes) = raw.split_at(raw.len() - 2);
    let expected_checksum = crc16_xmodem(body);
    let actual_checksum = (checksum_bytes[0] as u16) | ((checksum_bytes[1] as u16) << 8);
    if expected_checksum != actual_checksum {
        return Err(StrKeyError::BadChecksum);
    }
    let version = body[0];
    if version != expected_version {
        return Err(StrKeyError::WrongVersion);
    }
    Ok(body[1..].to_vec())
}

/// Encode a raw 32-byte ed25519 public key as a classic `G...` address.
pub fn encode_account_id(public_key: &[u8; 32]) -> String {
    encode(ACCOUNT_VERSION, public_key)
}

/// Decode a `G...` address back into its raw 32-byte ed25519 public key.
pub fn decode_account_id(address: &str) -> Result<[u8; 32], StrKeyError> {
    let payload = decode(ACCOUNT_VERSION, address)?;
    payload.try_into().map_err(|_| StrKeyError::BadLength)
}

/// Encode a muxed account: the master account's raw ed25519 public key plus
/// a per-customer 64-bit id, as an `M...` address (SEP-0023).
pub fn encode_muxed_account(master_public_key: &[u8; 32], customer_id: u64) -> String {
    let mut payload = Vec::with_capacity(40);
    payload.extend_from_slice(master_public_key);
    payload.extend_from_slice(&customer_id.to_be_bytes());
    encode(MUXED_VERSION, &payload)
}

/// Decode an `M...` address back into the master account's public key and
/// the per-customer id it encodes.
pub fn decode_muxed_account(address: &str) -> Result<([u8; 32], u64), StrKeyError> {
    let payload = decode(MUXED_VERSION, address)?;
    if payload.len() != 40 {
        return Err(StrKeyError::BadLength);
    }
    let mut pk = [0u8; 32];
    pk.copy_from_slice(&payload[..32]);
    let mut id_bytes = [0u8; 8];
    id_bytes.copy_from_slice(&payload[32..]);
    Ok((pk, u64::from_be_bytes(id_bytes)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_key() -> [u8; 32] {
        // Not a real/funded key — fixed bytes purely for round-trip testing.
        let mut k = [0u8; 32];
        for (i, b) in k.iter_mut().enumerate() {
            *b = i as u8;
        }
        k
    }

    #[test]
    fn account_id_round_trips() {
        let pk = sample_key();
        let addr = encode_account_id(&pk);
        assert!(addr.starts_with('G'));
        let decoded = decode_account_id(&addr).unwrap();
        assert_eq!(decoded, pk);
    }

    #[test]
    fn muxed_account_round_trips() {
        let pk = sample_key();
        let addr = encode_muxed_account(&pk, 424242);
        assert!(addr.starts_with('M'));
        let (decoded_pk, id) = decode_muxed_account(&addr).unwrap();
        assert_eq!(decoded_pk, pk);
        assert_eq!(id, 424242);
    }

    #[test]
    fn tampered_address_fails_checksum() {
        let pk = sample_key();
        let mut addr = encode_account_id(&pk);
        // Flip the last character — must break the checksum.
        let last = addr.pop().unwrap();
        let replacement = if last == 'A' { 'B' } else { 'A' };
        addr.push(replacement);
        assert_eq!(decode_account_id(&addr), Err(StrKeyError::BadChecksum));
    }

    #[test]
    fn wrong_prefix_is_rejected_as_account_id() {
        let pk = sample_key();
        let muxed = encode_muxed_account(&pk, 1);
        assert_eq!(decode_account_id(&muxed), Err(StrKeyError::WrongVersion));
    }

    #[test]
    fn each_customer_id_yields_a_distinct_address() {
        let pk = sample_key();
        let a = encode_muxed_account(&pk, 1);
        let b = encode_muxed_account(&pk, 2);
        assert_ne!(a, b);
    }
}
