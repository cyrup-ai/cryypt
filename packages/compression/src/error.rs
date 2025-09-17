//! Error types for the compression crate

use std::fmt;
use thiserror::Error;

/// Result type alias for compression operations
pub type Result<T> = std::result::Result<T, CompressionError>;

/// Main error type for all compression operations
#[derive(Error, Debug)]
pub enum CompressionError {
    /// Compression operation failed
    #[error("Compression failed: {0}")]
    CompressionFailed(String),

    /// Decompression operation failed
    #[error("Decompression failed: {0}")]
    DecompressionFailed(String),

    /// Invalid compression level
    #[error("Invalid compression level: {0}")]
    InvalidLevel(String),

    /// Invalid data format
    #[error("Invalid data format: {0}")]
    InvalidFormat(String),

    /// IO error wrapper
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    /// Generic internal error
    #[error("Internal error: {0}")]
    InternalError(String),
}

impl Clone for CompressionError {
    fn clone(&self) -> Self {
        match self {
            Self::CompressionFailed(s) => Self::CompressionFailed(s.clone()),
            Self::DecompressionFailed(s) => Self::DecompressionFailed(s.clone()),
            Self::InvalidLevel(s) => Self::InvalidLevel(s.clone()),
            Self::InvalidFormat(s) => Self::InvalidFormat(s.clone()),
            Self::IoError(e) => Self::InternalError(e.to_string()),
            Self::InternalError(s) => Self::InternalError(s.clone()),
        }
    }
}

impl CompressionError {
    /// Create a `CompressionFailed` error with a formatted message
    #[must_use]
    pub fn compression_failed(msg: impl fmt::Display) -> Self {
        Self::CompressionFailed(msg.to_string())
    }

    /// Create a `DecompressionFailed` error with a formatted message
    #[must_use]
    pub fn decompression_failed(msg: impl fmt::Display) -> Self {
        Self::DecompressionFailed(msg.to_string())
    }

    /// Create an `InvalidLevel` error with a formatted message
    #[must_use]
    pub fn invalid_level(msg: impl fmt::Display) -> Self {
        Self::InvalidLevel(msg.to_string())
    }

    /// Create an `InvalidFormat` error with a formatted message
    #[must_use]
    pub fn invalid_format(msg: impl fmt::Display) -> Self {
        Self::InvalidFormat(msg.to_string())
    }

    /// Create an `InternalError` with a formatted message
    #[must_use]
    pub fn internal(msg: impl fmt::Display) -> Self {
        Self::InternalError(msg.to_string())
    }
}
