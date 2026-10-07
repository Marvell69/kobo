pub mod derivation;
pub mod strkey;

pub use derivation::derive_stellar_signing_key;
pub use strkey::{
    decode_account_id, decode_muxed_account, encode_account_id, encode_muxed_account, StrKeyError,
};

/// The allowlisted operation types a relayed transaction may contain.
/// Kobo validates against this before relaying anything — it never inspects
/// operations to decide whether to *sign*, only whether to *relay*.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllowedOperation {
    Payment,
    PathPaymentStrictSend,
    PathPaymentStrictReceive,
    ChangeTrust,
    ManageSellOffer,
    ManageBuyOffer,
    InvokeHostFunction, // Soroban contract invocation (SEP-41 tokens, etc.)
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum EnvelopeError {
    #[error("transaction source account does not match the wallet")]
    SourceMismatch,
    #[error("transaction contains no signatures")]
    Unsigned,
    #[error("transaction contains an operation type outside the allowlist")]
    DisallowedOperation,
}

/// A stand-in for full XDR parsing: in the real implementation this wraps
/// `stellar-xdr`, decodes the envelope, and checks source account, presence
/// of signatures, and each operation's type against [`AllowedOperation`].
/// Kept as a trait here so `kobo-api` can be exercised in tests without
/// pulling in a full XDR parser.
pub trait EnvelopeValidator {
    fn validate(&self, transaction_xdr: &str, expected_source: &str) -> Result<(), EnvelopeError>;
}
