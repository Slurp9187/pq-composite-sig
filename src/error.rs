// xwing-sig/src/error.rs

//! Error types for xwing-sig operations.

use thiserror::Error;

/// Errors that can occur during xwing-sig operations.
#[derive(Error, Debug, Clone)]
pub enum Error {
    /// The ML-DSA signature verification failed.
    #[error("Invalid ML-DSA signature")]
    InvalidMlDsaSignature,

    /// The Ed25519 signature verification failed.
    #[error("Invalid Ed25519 signature")]
    InvalidEd25519Signature,

    /// The binding tag does not match the expected value.
    #[error("Binding tag mismatch")]
    BindingTagMismatch,

    /// The signature has an invalid length.
    #[error("Invalid signature length")]
    InvalidSignatureLength,

    /// Failed to generate the ML-DSA signature.
    #[error("ML-DSA signing failed")]
    MlDsaSignError,
}

/// Type alias for results in xwing-sig.
pub type Result<T> = core::result::Result<T, Error>;
