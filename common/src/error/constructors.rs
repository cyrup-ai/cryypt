//! Error constructors and methods

use super::types::{Error, ErrorInner, ErrorKind};
use std::fmt;
use std::sync::Arc;

impl Error {
    /// Create a new error with the given kind
    pub fn new(kind: ErrorKind) -> Self {
        Self {
            inner: Arc::new(ErrorInner {
                kind,
                context: None,
                source: None,
                #[cfg(feature = "full-backtrace")]
                backtrace: backtrace::Backtrace::new(),
            }),
        }
    }

    /// Create an error with a source error
    pub fn with_source<E>(kind: ErrorKind, source: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self {
            inner: Arc::new(ErrorInner {
                kind,
                context: None,
                source: Some(Box::new(source)),
                #[cfg(feature = "full-backtrace")]
                backtrace: backtrace::Backtrace::new(),
            }),
        }
    }

    /// Add context to this error
    pub fn context<C: fmt::Display>(self, context: C) -> Self {
        // Create a new error with context, preserving the original
        Self {
            inner: Arc::new(ErrorInner {
                kind: self.inner.kind.clone(),
                context: Some(context.to_string()),
                source: self
                    .inner
                    .source
                    .as_ref()
                    .map(|_| Box::new(self.clone()) as Box<dyn std::error::Error + Send + Sync>),
                #[cfg(feature = "full-backtrace")]
                backtrace: backtrace::Backtrace::new(),
            }),
        }
    }

    /// Get the error kind
    pub fn kind(&self) -> &ErrorKind {
        &self.inner.kind
    }

    /// Get the error context if any
    pub fn get_context(&self) -> Option<&str> {
        self.inner.context.as_deref()
    }

    /// Get the backtrace
    #[cfg(feature = "full-backtrace")]
    pub fn backtrace(&self) -> &backtrace::Backtrace {
        &self.inner.backtrace
    }

    /// Create an I/O error
    pub fn io() -> Self {
        Self::new(ErrorKind::Io)
    }

    /// Create a crypto error
    pub fn crypto() -> Self {
        Self::new(ErrorKind::Crypto)
    }

    /// Create a key management error
    pub fn key_management() -> Self {
        Self::new(ErrorKind::KeyManagement)
    }

    /// Create a compression error
    pub fn compression() -> Self {
        Self::new(ErrorKind::Compression)
    }

    /// Create a network error
    pub fn network() -> Self {
        Self::new(ErrorKind::Network)
    }

    /// Create a configuration error
    pub fn configuration() -> Self {
        Self::new(ErrorKind::Configuration)
    }

    /// Create a validation error
    pub fn validation() -> Self {
        Self::new(ErrorKind::Validation)
    }

    /// Create a resource exhausted error
    pub fn resource_exhausted() -> Self {
        Self::new(ErrorKind::ResourceExhausted)
    }

    /// Create a timeout error
    pub fn timeout() -> Self {
        Self::new(ErrorKind::Timeout)
    }

    /// Create a permission denied error
    pub fn permission_denied() -> Self {
        Self::new(ErrorKind::PermissionDenied)
    }

    /// Create a not found error
    pub fn not_found() -> Self {
        Self::new(ErrorKind::NotFound)
    }

    /// Create an already exists error
    pub fn already_exists() -> Self {
        Self::new(ErrorKind::AlreadyExists)
    }

    /// Create an internal error
    pub fn internal() -> Self {
        Self::new(ErrorKind::Internal)
    }

    /// Create an other error with custom message
    pub fn other<S: Into<String>>(msg: S) -> Self {
        Self::new(ErrorKind::Other(msg.into()))
    }
}
