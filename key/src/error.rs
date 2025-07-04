//! Error types for the key management crate

use std::fmt;
use thiserror::Error;

/// Result type alias for key operations
pub type Result<T> = std::result::Result<T, KeyError>;

/// Main error type for all key management operations
#[derive(Error, Debug)]
pub enum KeyError {
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

    /// Key generation failed
    #[error("Key generation failed: {0}")]
    KeyGenerationFailed(String),

    /// Key derivation failed
    #[error("Key derivation failed: {0}")]
    KeyDerivationFailed(String),

    /// Invalid key size
    #[error("Invalid key size: expected {expected}, got {actual}")]
    InvalidKeySize {
        /// Expected key size
        expected: usize,
        /// Actual key size provided
        actual: usize,
    },

    /// Key rotation failed
    #[error("Key rotation failed: {0}")]
    KeyRotationFailed(String),

    /// Insufficient entropy for secure operation
    #[error("Insufficient entropy: minimum quality not met")]
    InsufficientEntropy,

    /// Serialization/deserialization error
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// Storage error
    #[error("Storage error: {0}")]
    StorageError(String),

    /// Encryption failed
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),

    /// Decryption failed
    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),

    /// IO error wrapper
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    /// IO error with message
    #[error("IO error: {0}")]
    Io(String),

    /// Keychain error
    #[error("Keychain error: {0}")]
    KeychainError(String),

    /// Generic internal error
    #[error("Internal error: {0}")]
    InternalError(String),
}

impl KeyError {
    /// Create an InvalidKey error with a formatted message
    pub fn invalid_key(msg: impl fmt::Display) -> Self {
        Self::InvalidKey(msg.to_string())
    }

    /// Create a KeyGenerationFailed error with a formatted message
    pub fn key_generation_failed(msg: impl fmt::Display) -> Self {
        Self::KeyGenerationFailed(msg.to_string())
    }

    /// Create a KeyDerivationFailed error with a formatted message
    pub fn key_derivation_failed(msg: impl fmt::Display) -> Self {
        Self::KeyDerivationFailed(msg.to_string())
    }

    /// Create a KeyRotationFailed error with a formatted message
    pub fn key_rotation_failed(msg: impl fmt::Display) -> Self {
        Self::KeyRotationFailed(msg.to_string())
    }

    /// Create a SerializationError with a formatted message
    pub fn serialization_error(msg: impl fmt::Display) -> Self {
        Self::SerializationError(msg.to_string())
    }

    /// Create a StorageError with a formatted message
    pub fn storage_error(msg: impl fmt::Display) -> Self {
        Self::StorageError(msg.to_string())
    }

    /// Create a KeychainError with a formatted message
    pub fn keychain_error(msg: impl fmt::Display) -> Self {
        Self::KeychainError(msg.to_string())
    }

    /// Create an InternalError with a formatted message
    pub fn internal(msg: impl fmt::Display) -> Self {
        Self::InternalError(msg.to_string())
    }

    /// Create a KeyNotFound error with a key ID
    pub fn key_not_found(id: impl Into<String>) -> Self {
        Self::KeyNotFound {
            id: id.into(),
            version: None,
        }
    }
}

// Implement conversions from common error types

impl From<serde_json::Error> for KeyError {
    fn from(err: serde_json::Error) -> Self {
        Self::SerializationError(err.to_string())
    }
}

impl From<keyring::Error> for KeyError {
    fn from(err: keyring::Error) -> Self {
        Self::KeychainError(err.to_string())
    }
}
