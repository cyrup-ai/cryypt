//! Comprehensive error handling for cipher module

use thiserror::Error;

/// Cipher-specific errors
#[derive(Debug, Error)]
pub enum CipherError {
    /// HKDF expansion operation failed
    #[error("HKDF expansion error: {0}")]
    HkdfExpansion(String),

    /// HMAC operation failed
    #[error("HMAC error: {0}")]
    Hmac(String),

    /// Nonce generation failed
    #[error("Nonce generation error: {0}")]
    NonceGeneration(String),

    /// Key derivation operation failed
    #[error("Key derivation error: {0}")]
    KeyDerivation(String),

    /// Encryption operation failed
    #[error("Encryption error: {0}")]
    Encryption(String),

    /// Decryption operation failed
    #[error("Decryption error: {0}")]
    Decryption(String),

    /// Invalid key length provided
    #[error("Invalid key length: expected {expected}, got {actual}")]
    InvalidKeyLength {
        /// Expected key length in bytes
        expected: usize,
        /// Actual key length in bytes
        actual: usize,
    },

    /// Invalid nonce length provided
    #[error("Invalid nonce length: expected {expected}, got {actual}")]
    InvalidNonceLength {
        /// Expected nonce length in bytes
        expected: usize,
        /// Actual nonce length in bytes
        actual: usize,
    },

    /// Cryptographic operation failed
    #[error("Cryptographic operation failed: {0}")]
    CryptoOperation(String),

    /// Hex decoding operation failed
    #[error("Hex decoding error: {0}")]
    HexDecode(String),

    /// Nonce operation failed
    #[error("Nonce error: {0}")]
    Nonce(String),

    /// Invalid key size provided (async pattern)
    #[error("Invalid key size: expected {expected}, got {actual}")]
    InvalidKeySize {
        /// Expected key size in bytes
        expected: usize,
        /// Actual key size in bytes
        actual: usize,
    },

    /// Encryption operation failed (async pattern)
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),

    /// Decryption operation failed (async pattern)
    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),

    /// Invalid encrypted data provided
    #[error("Invalid encrypted data: {0}")]
    InvalidEncryptedData(String),

    /// Invalid nonce provided
    #[error("Invalid nonce: {0}")]
    InvalidNonce(String),

    /// Unsupported cryptographic algorithm
    #[error("Unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),

    /// Internal error occurred
    #[error("Internal error: {0}")]
    Internal(String),

    /// I/O operation failed
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

impl From<hex::FromHexError> for CipherError {
    fn from(err: hex::FromHexError) -> Self {
        CipherError::HexDecode(err.to_string())
    }
}

impl From<base64::DecodeError> for CipherError {
    fn from(err: base64::DecodeError) -> Self {
        CipherError::InvalidEncryptedData(format!("Base64 decode error: {err}"))
    }
}

/// Result type for cipher operations
pub type Result<T> = std::result::Result<T, CipherError>;
