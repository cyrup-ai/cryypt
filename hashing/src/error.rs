//! Error types for the hashing crate

use std::fmt;
use thiserror::Error;

/// Result type alias for hashing operations
pub type Result<T> = std::result::Result<T, HashError>;

/// Main error type for all hashing operations
#[derive(Error, Debug)]
pub enum HashError {
    /// Invalid parameters provided
    #[error("Invalid parameters: {0}")]
    InvalidParameters(String),

    /// Invalid salt size
    #[error("Invalid salt size: expected {expected}, got {actual}")]
    InvalidSaltSize {
        /// Expected salt size
        expected: usize,
        /// Actual salt size provided
        actual: usize,
    },

    /// Key derivation failed
    #[error("Key derivation failed: {0}")]
    KeyDerivationFailed(String),

    /// Insufficient entropy for secure operation
    #[error("Insufficient entropy: minimum quality not met")]
    InsufficientEntropy,

    /// Generic internal error
    #[error("Internal error: {0}")]
    InternalError(String),
}

impl HashError {
    /// Create an InvalidParameters error with a formatted message
    pub fn invalid_parameters(msg: impl fmt::Display) -> Self {
        Self::InvalidParameters(msg.to_string())
    }

    /// Create a KeyDerivationFailed error with a formatted message
    pub fn key_derivation_failed(msg: impl fmt::Display) -> Self {
        Self::KeyDerivationFailed(msg.to_string())
    }

    /// Create an InternalError with a formatted message
    pub fn internal(msg: impl fmt::Display) -> Self {
        Self::InternalError(msg.to_string())
    }
}

// Implement conversions from common error types

impl From<argon2::password_hash::Error> for HashError {
    fn from(err: argon2::password_hash::Error) -> Self {
        Self::KeyDerivationFailed(format!("Argon2 error: {}", err))
    }
}