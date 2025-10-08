//! Comprehensive error handling for hashing module

use thiserror::Error;

/// Hashing-specific errors
#[derive(Debug, Error)]
pub enum HashError {
    #[error("MAC initialization error: {0}")]
    MacInitialization(String),

    #[error("Hash computation error: {0}")]
    HashComputation(String),

    #[error("Invalid key length for MAC: expected {expected}, got {actual}")]
    InvalidMacKeyLength { expected: usize, actual: usize },

    #[error("Stream processing error: {0}")]
    StreamProcessing(String),

    #[error("Hash verification failed")]
    VerificationFailed,

    #[error("Unsupported hash algorithm: {0}")]
    UnsupportedAlgorithm(String),

    #[error("Hash finalization error: {0}")]
    Finalization(String),

    #[error("Internal error: {0}")]
    Internal(String),

    #[error("Invalid parameters: {0}")]
    InvalidParameters(String),
}

impl HashError {
    /// Create an internal error (legacy compatibility)
    #[must_use]
    pub fn internal(msg: impl Into<String>) -> Self {
        Self::Internal(msg.into())
    }

    /// Create an `invalid_parameters` error (legacy compatibility)
    #[must_use]
    pub fn invalid_parameters(msg: impl Into<String>) -> Self {
        Self::InvalidParameters(msg.into())
    }
}

/// Result type for hashing operations
pub type Result<T> = std::result::Result<T, HashError>;
