//! Error handling with context propagation
//!
//! Provides a comprehensive error handling system with:
//! - Error chaining and context preservation
//! - Backtrace capture and display
//! - Structured error types with thiserror
//! - Context attachment for debugging

use std::fmt;
use thiserror::Error;
use std::sync::Arc;

/// Core error type with context propagation support
#[derive(Debug, Clone)]
pub struct Error {
    /// The actual error
    inner: Arc<ErrorInner>,
}

#[derive(Debug)]
struct ErrorInner {
    /// The error kind
    kind: ErrorKind,
    /// Optional error context
    context: Option<String>,
    /// Optional source error
    source: Option<Box<dyn std::error::Error + Send + Sync>>,
    /// Backtrace captured at error creation
    #[cfg(feature = "full-backtrace")]
    backtrace: backtrace::Backtrace,
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
                source: self.inner.source.as_ref().map(|_| {
                    Box::new(self.clone()) as Box<dyn std::error::Error + Send + Sync>
                }),
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

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.inner.kind)?;
        
        if let Some(context) = &self.inner.context {
            write!(f, ": {}", context)?;
        }
        
        if let Some(source) = &self.inner.source {
            write!(f, "\nCaused by: {}", source)?;
        }
        
        Ok(())
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.inner.source.as_ref().map(|e| e.as_ref() as &(dyn std::error::Error + 'static))
    }
}

/// Result type alias using our Error
pub type Result<T> = std::result::Result<T, Error>;

/// Extension trait for adding context to Results
pub trait ResultExt<T> {
    /// Add context to an error
    fn context<C: fmt::Display>(self, context: C) -> Result<T>;
    
    /// Add context with a closure (only called on error)
    fn with_context<C, F>(self, f: F) -> Result<T>
    where
        C: fmt::Display,
        F: FnOnce() -> C;
}

impl<T, E> ResultExt<T> for std::result::Result<T, E>
where
    E: std::error::Error + Send + Sync + 'static,
{
    fn context<C: fmt::Display>(self, context: C) -> Result<T> {
        self.map_err(|e| Error::with_source(ErrorKind::Internal, e).context(context))
    }
    
    fn with_context<C, F>(self, f: F) -> Result<T>
    where
        C: fmt::Display,
        F: FnOnce() -> C,
    {
        self.map_err(|e| Error::with_source(ErrorKind::Internal, e).context(f()))
    }
}

/// Extension trait for Options to convert to Results with context
pub trait OptionExt<T> {
    /// Convert None to an error with context
    fn context<C: fmt::Display>(self, context: C) -> Result<T>;
    
    /// Convert None to an error with a closure for context
    fn with_context<C, F>(self, f: F) -> Result<T>
    where
        C: fmt::Display,
        F: FnOnce() -> C;
}

impl<T> OptionExt<T> for Option<T> {
    fn context<C: fmt::Display>(self, context: C) -> Result<T> {
        self.ok_or_else(|| Error::not_found().context(context))
    }
    
    fn with_context<C, F>(self, f: F) -> Result<T>
    where
        C: fmt::Display,
        F: FnOnce() -> C,
    {
        self.ok_or_else(|| Error::not_found().context(f()))
    }
}

/// Macro for creating errors with automatic file/line context
#[macro_export]
macro_rules! err {
    ($kind:ident) => {
        $crate::error::Error::$kind().context(format!("at {}:{}", file!(), line!()))
    };
    ($kind:ident, $msg:expr) => {
        $crate::error::Error::$kind().context(format!("{} at {}:{}", $msg, file!(), line!()))
    };
    ($kind:ident, $fmt:expr, $($arg:tt)*) => {
        $crate::error::Error::$kind().context(format!(concat!($fmt, " at {}:{}"), $($arg)*, file!(), line!()))
    };
}

/// Macro for bailing out with an error
#[macro_export]
macro_rules! bail {
    ($($arg:tt)*) => {
        return Err($crate::err!($($arg)*))
    };
}

/// Macro for ensuring a condition holds
#[macro_export]
macro_rules! ensure {
    ($cond:expr, $($arg:tt)*) => {
        if !$cond {
            $crate::bail!($($arg)*);
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_error_creation() {
        let err = Error::io().context("Failed to read file");
        assert!(matches!(err.kind(), ErrorKind::Io));
        assert_eq!(err.get_context(), Some("Failed to read file"));
    }
    
    #[test]
    fn test_error_chaining() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let err = Error::with_source(ErrorKind::Io, io_err)
            .context("Failed to open config file");
        
        assert!(matches!(err.kind(), ErrorKind::Io));
        assert!(std::error::Error::source(&err).is_some());
    }
    
    #[test]
    fn test_result_extension() {
        let result: std::result::Result<(), std::io::Error> = Err(
            std::io::Error::new(std::io::ErrorKind::PermissionDenied, "access denied")
        );
        
        let err = result.context("Cannot access system file").unwrap_err();
        assert!(err.get_context().unwrap().contains("Cannot access system file"));
    }
    
    #[test]
    fn test_option_extension() {
        let opt: Option<i32> = None;
        let err = opt.context("Value not found in cache").unwrap_err();
        assert!(matches!(err.kind(), ErrorKind::NotFound));
        assert_eq!(err.get_context(), Some("Value not found in cache"));
    }
    
    #[test]
    fn test_error_macros() {
        fn test_function() -> Result<()> {
            ensure!(1 + 1 == 3, validation, "Math is broken");
            Ok(())
        }
        
        let err = test_function().unwrap_err();
        assert!(matches!(err.kind(), ErrorKind::Validation));
        assert!(err.get_context().unwrap().contains("Math is broken"));
    }
}