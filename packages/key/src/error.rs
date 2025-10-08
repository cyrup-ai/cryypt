//! Comprehensive error handling for key module

use thiserror::Error;

/// Key-specific errors
#[derive(Debug, Error)]
pub enum KeyError {
    /// Entropy source initialization failed
    #[error("Entropy source initialization failed: {0}")]
    EntropyInitialization(String),

    /// Key generation error occurred  
    #[error("Key generation error: {0}")]
    KeyGeneration(String),

    /// Key derivation error occurred
    #[error("Key derivation error: {0}")]
    KeyDerivation(String),

    /// Invalid key format provided
    #[error("Invalid key format: {0}")]
    InvalidKeyFormat(String),

    /// Key storage operation failed
    #[error("Key storage error: {0}")]
    KeyStorage(String),

    /// Key retrieval operation failed
    #[error("Key retrieval error: {0}")]
    KeyRetrieval(String),

    /// Insufficient entropy for secure operation
    #[error("Insufficient entropy: {0}")]
    InsufficientEntropy(String),

    /// Random number generation failed
    #[error("Random number generation failed: {0}")]
    RandomGeneration(String),

    /// Invalid key provided
    #[error("Invalid key: {0}")]
    InvalidKey(String),

    /// Encryption operation failed
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),

    /// Decryption operation failed
    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),

    /// I/O operation failed
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Internal error occurred
    #[error("Internal error: {0}")]
    Internal(String),

    /// Invalid key size provided
    #[error("Invalid key size: expected {expected}, got {actual}")]
    InvalidKeySize {
        /// Expected key size in bytes
        expected: usize,
        /// Actual key size in bytes
        actual: usize,
    },

    /// Key not found in storage
    #[error("Key not found: id={id}, version={version}")]
    KeyNotFound {
        /// Key identifier
        id: String,
        /// Key version number
        version: u32,
    },

    /// Storage backend error occurred
    #[error("Storage backend error: {operation} failed - {details}")]
    StorageBackendError {
        /// The storage operation that failed
        operation: String,
        /// Detailed error information
        details: String,
    },

    /// Storage backend is temporarily unavailable
    #[error("Storage temporarily unavailable: {reason}")]
    StorageUnavailable {
        /// Reason for unavailability
        reason: String,
    },

    /// Storage backend connection failed
    #[error("Storage connection failed: {backend_type} - {details}")]
    StorageConnectionFailed {
        /// Type of storage backend
        backend_type: String,
        /// Connection failure details
        details: String,
    },
}

impl KeyError {
    /// Create an `invalid_key` error (legacy compatibility)
    pub fn invalid_key(msg: impl Into<String>) -> Self {
        Self::InvalidKey(msg.into())
    }

    /// Create an internal error (legacy compatibility)
    pub fn internal(msg: impl Into<String>) -> Self {
        Self::Internal(msg.into())
    }
}

/// Result type for key operations
pub type Result<T> = std::result::Result<T, KeyError>;
