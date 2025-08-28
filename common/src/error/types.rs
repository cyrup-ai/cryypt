//! Core error types and definitions

use std::sync::Arc;
use thiserror::Error;

/// Core error type with context propagation support
#[derive(Debug, Clone)]
pub struct Error {
    /// The actual error
    pub(super) inner: Arc<ErrorInner>,
}

#[derive(Debug)]
pub(super) struct ErrorInner {
    /// The error kind
    pub kind: ErrorKind,
    /// Optional error context
    pub context: Option<String>,
    /// Optional source error
    pub source: Option<Box<dyn std::error::Error + Send + Sync>>,
    /// Backtrace captured at error creation
    #[cfg(feature = "full-backtrace")]
    pub backtrace: backtrace::Backtrace,
}

/// Different kinds of errors that can occur
#[derive(Debug, Clone, Error)]
pub enum ErrorKind {
    /// I/O related errors
    #[error("I/O error")]
    Io,

    /// Cryptographic operation errors
    #[error("Cryptographic error")]
    Crypto,

    /// Key management errors
    #[error("Key management error")]
    KeyManagement,

    /// Compression/decompression errors
    #[error("Compression error")]
    Compression,

    /// Network related errors
    #[error("Network error")]
    Network,

    /// Configuration errors
    #[error("Configuration error")]
    Configuration,

    /// Validation errors
    #[error("Validation error")]
    Validation,

    /// Resource exhaustion
    #[error("Resource exhausted")]
    ResourceExhausted,

    /// Operation timeout
    #[error("Operation timed out")]
    Timeout,

    /// Permission denied
    #[error("Permission denied")]
    PermissionDenied,

    /// Not found
    #[error("Not found")]
    NotFound,

    /// Already exists
    #[error("Already exists")]
    AlreadyExists,

    /// Internal error
    #[error("Internal error")]
    Internal,

    /// Other error with custom message
    #[error("{0}")]
    Other(String),
}

/// Result type alias using our Error
pub type Result<T> = std::result::Result<T, Error>;
