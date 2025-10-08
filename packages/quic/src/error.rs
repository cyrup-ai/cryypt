//! Comprehensive error handling for QUIC module

use thiserror::Error;

/// QUIC-specific errors
#[derive(Debug, Error)]
pub enum QuicError {
    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Network error: {0}")]
    Network(#[from] std::io::Error),

    #[error("Connection error: {0}")]
    Connection(String),

    #[error("Certificate error: {0}")]
    Certificate(String),

    #[error("Protocol error: {0}")]
    Protocol(String),

    #[error("Address parsing error: {0}")]
    AddressParse(#[from] std::net::AddrParseError),

    #[error("QUIC library error: {0}")]
    QuicLib(String),

    #[error("Timeout error: {0}")]
    Timeout(String),

    #[error("Invalid state: {0}")]
    InvalidState(String),

    #[error("Quiche error: {0}")]
    Quiche(String),

    #[error("Timeout elapsed: {0}")]
    TimeoutElapsed(String),

    #[error("Internal error: {0}")]
    Internal(String),

    #[error("Certificate invalid: {0}")]
    CertificateInvalid(String),

    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("Cryptographic error: {0}")]
    Crypto(String),

    #[error("Hash computation failed: {0}")]
    HashFailure(String),

    #[error("Key derivation failed: {0}")]
    KeyDerivation(String),

    #[error("Insufficient cryptographic data: {0}")]
    InsufficientCryptoData(String),
}

impl QuicError {
    /// Create an Internal error (legacy compatibility)
    pub fn internal(msg: impl Into<String>) -> Self {
        Self::Internal(msg.into())
    }

    /// Create a `CertificateInvalid` error (legacy compatibility)
    pub fn certificate_invalid(msg: impl Into<String>) -> Self {
        Self::CertificateInvalid(msg.into())
    }

    /// Create a Crypto error
    pub fn crypto(msg: impl Into<String>) -> Self {
        Self::Crypto(msg.into())
    }

    /// Create a `HashFailure` error
    pub fn hash_failure(msg: impl Into<String>) -> Self {
        Self::HashFailure(msg.into())
    }

    /// Create a `KeyDerivation` error
    pub fn key_derivation(msg: impl Into<String>) -> Self {
        Self::KeyDerivation(msg.into())
    }

    /// Create an `InsufficientCryptoData` error
    pub fn insufficient_crypto_data(msg: impl Into<String>) -> Self {
        Self::InsufficientCryptoData(msg.into())
    }
}

impl From<quiche::Error> for QuicError {
    fn from(err: quiche::Error) -> Self {
        QuicError::Quiche(format!("{err:?}"))
    }
}

impl From<tokio::time::error::Elapsed> for QuicError {
    fn from(err: tokio::time::error::Elapsed) -> Self {
        QuicError::TimeoutElapsed(err.to_string())
    }
}

impl From<String> for QuicError {
    fn from(err: String) -> Self {
        QuicError::Protocol(err)
    }
}

impl From<&str> for QuicError {
    fn from(err: &str) -> Self {
        QuicError::Protocol(err.to_string())
    }
}

/// Legacy error type alias for backwards compatibility
pub type CryptoTransportError = QuicError;

/// Result type for QUIC operations
pub type Result<T> = std::result::Result<T, QuicError>;
