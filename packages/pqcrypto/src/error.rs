//! Error types for the post-quantum cryptography crate

use std::fmt;
use thiserror::Error;

/// Result type alias for post-quantum cryptography operations
pub type Result<T> = std::result::Result<T, PqCryptoError>;

/// Main error type for all post-quantum cryptographic operations
#[derive(Error, Debug)]
pub enum PqCryptoError {
    /// Invalid key or key-related error
    #[error("Invalid key: {0}")]
    InvalidKey(String),

    /// Key generation failed
    #[error("Key generation failed: {0}")]
    KeyGenerationFailed(String),

    /// Encapsulation operation failed
    #[error("Encapsulation failed: {0}")]
    EncapsulationFailed(String),

    /// Decapsulation operation failed
    #[error("Decapsulation failed: {0}")]
    DecapsulationFailed(String),

    /// Invalid or corrupted ciphertext
    #[error("Invalid ciphertext: {0}")]
    InvalidCiphertext(String),

    /// Signature generation failed
    #[error("Signature generation failed: {0}")]
    SignatureFailed(String),

    /// Signature verification failed
    #[error("Signature verification failed: {0}")]
    VerificationFailed(String),

    /// Authentication/verification failed (e.g., signature mismatch)
    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),

    /// Invalid or corrupted encrypted data
    #[error("Invalid encrypted data: {0}")]
    InvalidEncryptedData(String),

    /// Unsupported algorithm
    #[error("Unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),

    /// Invalid algorithm parameters
    #[error("Invalid parameters: {0}")]
    InvalidParameters(String),

    /// Invalid key size
    #[error("Invalid key size: expected {expected}, got {actual}")]
    InvalidKeySize {
        /// Expected key size
        expected: usize,
        /// Actual key size provided
        actual: usize,
    },

    /// Data too short for the operation
    #[error("Data too short: minimum {minimum} bytes required, got {actual}")]
    DataTooShort {
        /// Minimum required size
        minimum: usize,
        /// Actual size provided
        actual: usize,
    },

    /// Serialization/deserialization error
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// Random number generation failed
    #[error("Random generation failed: {0}")]
    RandomGenerationFailed(String),

    /// IO error with string message
    #[error("IO error: {0}")]
    Io(String),

    /// Generic internal error
    #[error("Internal error: {0}")]
    InternalError(String),

    /// Invalid input provided
    #[error("Invalid input: {0}")]
    InvalidInput(String),
}

impl PqCryptoError {
    /// Create an `InvalidKey` error with a formatted message
    pub fn invalid_key(msg: impl fmt::Display) -> Self {
        Self::InvalidKey(msg.to_string())
    }

    /// Create an `EncapsulationFailed` error with a formatted message
    pub fn encapsulation_failed(msg: impl fmt::Display) -> Self {
        Self::EncapsulationFailed(msg.to_string())
    }

    /// Create a `DecapsulationFailed` error with a formatted message
    pub fn decapsulation_failed(msg: impl fmt::Display) -> Self {
        Self::DecapsulationFailed(msg.to_string())
    }

    /// Create an `InvalidCiphertext` error with a formatted message
    pub fn invalid_ciphertext(msg: impl fmt::Display) -> Self {
        Self::InvalidCiphertext(msg.to_string())
    }

    /// Create a `SignatureFailed` error with a formatted message
    pub fn signature_failed(msg: impl fmt::Display) -> Self {
        Self::SignatureFailed(msg.to_string())
    }

    /// Create a `VerificationFailed` error with a formatted message
    pub fn verification_failed(msg: impl fmt::Display) -> Self {
        Self::VerificationFailed(msg.to_string())
    }

    /// Create an `AuthenticationFailed` error with a formatted message
    pub fn auth_failed(msg: impl fmt::Display) -> Self {
        Self::AuthenticationFailed(msg.to_string())
    }

    /// Create an `InvalidEncryptedData` error with a formatted message
    pub fn invalid_encrypted_data(msg: impl fmt::Display) -> Self {
        Self::InvalidEncryptedData(msg.to_string())
    }

    /// Create a `SerializationError` with a formatted message
    pub fn serialization_error(msg: impl fmt::Display) -> Self {
        Self::SerializationError(msg.to_string())
    }

    /// Create an `InternalError` with a formatted message
    pub fn internal(msg: impl fmt::Display) -> Self {
        Self::InternalError(msg.to_string())
    }
}

// Implement conversions from common error types

impl From<serde_json::Error> for PqCryptoError {
    fn from(err: serde_json::Error) -> Self {
        Self::SerializationError(err.to_string())
    }
}

impl From<base64::DecodeError> for PqCryptoError {
    fn from(err: base64::DecodeError) -> Self {
        Self::InvalidEncryptedData(format!("Base64 decode error: {err}"))
    }
}

impl From<hex::FromHexError> for PqCryptoError {
    fn from(err: hex::FromHexError) -> Self {
        Self::InvalidEncryptedData(format!("Hex decode error: {err}"))
    }
}
