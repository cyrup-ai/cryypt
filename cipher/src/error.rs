//! Error types for the crypt crate

use std::fmt;
use thiserror::Error;

/// Result type alias for crypt operations
pub type Result<T> = std::result::Result<T, CryptError>;

/// Main error type for all cryptographic operations
#[derive(Error, Debug)]
pub enum CryptError {
    /// Invalid key or key-related error
    #[error("Invalid key: {0}")]
    InvalidKey(String),

    /// Key not found in the key store
    #[error("Key not found: {id} (version: {version:?})")]
    KeyNotFound {
        /// The key ID that was not found
        id: String,
        /// The version that was requested
        version: Option<u32>,
    },

    /// Key version is too old for the operation
    #[error("Key version {actual} is too old (minimum required: {required})")]
    KeyVersionTooOld {
        /// The actual version of the key
        actual: u32,
        /// The minimum required version
        required: u32,
    },

    /// Encryption operation failed
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),

    /// Decryption operation failed
    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),

    /// Invalid or corrupted encrypted data
    #[error("Invalid encrypted data: {0}")]
    InvalidEncryptedData(String),

    /// Authentication/verification failed (e.g., MAC mismatch)
    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),

    /// Unsupported cipher algorithm
    #[error("Unsupported algorithm: {0:?}")]
    UnsupportedAlgorithm(String),

    /// Unsupported operation for the current configuration
    #[error("Unsupported operation: {0}")]
    UnsupportedOperation(String),

    /// Invalid algorithm parameters
    #[error("Invalid parameters: {0}")]
    InvalidParameters(String),

    /// Serialization/deserialization error
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// Key derivation failed
    #[error("Key derivation failed: {0}")]
    KeyDerivationFailed(String),

    /// Random number generation failed
    #[error("Random generation failed: {0}")]
    RandomGenerationFailed(String),

    /// Insufficient entropy for secure operation
    #[error("Insufficient entropy: minimum quality not met")]
    InsufficientEntropy,

    /// Invalid nonce
    #[error("Invalid nonce: {0}")]
    InvalidNonce(String),

    /// Invalid nonce size
    #[error("Invalid nonce size: expected {expected}, got {actual}")]
    InvalidNonceSize {
        /// Expected nonce size
        expected: usize,
        /// Actual nonce size provided
        actual: usize,
    },

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

    /// Key rotation failed
    #[error("Key rotation failed: {0}")]
    KeyRotationFailed(String),

    /// Invalid configuration
    #[error("Invalid configuration: {0}")]
    InvalidConfiguration(String),

    /// IO error wrapper
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    /// Simple IO error with string message
    #[error("IO error: {0}")]
    Io(String),

    /// Key management error
    #[error("Key management error: {0}")]
    KeyManagement(String),

    /// Compression error
    #[error("Compression error: {0}")]
    CompressionError(String),

    /// Generic internal error
    #[error("Internal error: {0}")]
    InternalError(String),
}

impl CryptError {
    /// Create an InvalidKey error with a formatted message
    pub fn invalid_key(msg: impl fmt::Display) -> Self {
        Self::InvalidKey(msg.to_string())
    }

    /// Create an EncryptionFailed error with a formatted message
    pub fn encryption_failed(msg: impl fmt::Display) -> Self {
        Self::EncryptionFailed(msg.to_string())
    }

    /// Create a DecryptionFailed error with a formatted message
    pub fn decryption_failed(msg: impl fmt::Display) -> Self {
        Self::DecryptionFailed(msg.to_string())
    }

    /// Create an InvalidEncryptedData error with a formatted message
    pub fn invalid_encrypted_data(msg: impl fmt::Display) -> Self {
        Self::InvalidEncryptedData(msg.to_string())
    }

    /// Create an AuthenticationFailed error with a formatted message
    pub fn auth_failed(msg: impl fmt::Display) -> Self {
        Self::AuthenticationFailed(msg.to_string())
    }

    /// Create a KeyDerivationFailed error with a formatted message
    pub fn key_derivation_failed(msg: impl fmt::Display) -> Self {
        Self::KeyDerivationFailed(msg.to_string())
    }

    /// Create a SerializationError with a formatted message
    pub fn serialization_error(msg: impl fmt::Display) -> Self {
        Self::SerializationError(msg.to_string())
    }

    /// Create an InternalError with a formatted message
    pub fn internal(msg: impl fmt::Display) -> Self {
        Self::InternalError(msg.to_string())
    }

    /// Create a compression error
    pub fn compression(msg: impl fmt::Display) -> Self {
        Self::InternalError(format!("Compression error: {}", msg))
    }

    /// Create a decompression error
    pub fn decompression(msg: impl fmt::Display) -> Self {
        Self::InternalError(format!("Decompression error: {}", msg))
    }
}

// Implement conversions from common error types

impl From<serde_json::Error> for CryptError {
    fn from(err: serde_json::Error) -> Self {
        Self::SerializationError(err.to_string())
    }
}

impl From<base64::DecodeError> for CryptError {
    fn from(err: base64::DecodeError) -> Self {
        Self::InvalidEncryptedData(format!("Base64 decode error: {}", err))
    }
}

impl From<hex::FromHexError> for CryptError {
    fn from(err: hex::FromHexError) -> Self {
        Self::InvalidEncryptedData(format!("Hex decode error: {}", err))
    }
}

impl From<argon2::password_hash::Error> for CryptError {
    fn from(err: argon2::password_hash::Error) -> Self {
        Self::KeyDerivationFailed(format!("Argon2 error: {}", err))
    }
}

impl From<cryypt_key::KeyError> for CryptError {
    fn from(e: cryypt_key::KeyError) -> Self {
        Self::KeyManagement(e.to_string())
    }
}

impl From<cryypt_compression::CompressionError> for CryptError {
    fn from(e: cryypt_compression::CompressionError) -> Self {
        Self::CompressionError(e.to_string())
    }
}
