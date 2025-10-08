//! Secure error handling module
//!
//! Provides secure error handling that prevents information leakage while maintaining
//! useful debugging information for legitimate users and administrators.

use std::fmt;
use thiserror::Error;

/// Security-focused error types
#[derive(Error, Debug)]
pub enum SecurityError {
    #[error("Access denied")]
    AccessDenied,

    #[error("Authentication failed")]
    AuthenticationFailed,

    #[error("Invalid input provided")]
    InvalidInput,

    #[error("Operation not permitted")]
    OperationNotPermitted,

    #[error("Resource not found")]
    ResourceNotFound,

    #[error("Internal security error")]
    InternalSecurityError,

    #[error("Rate limit exceeded")]
    RateLimitExceeded,

    #[error("Cryptographic operation failed")]
    CryptographicFailure,
}

/// Error sanitization levels
#[derive(Debug, Clone, Copy)]
pub enum ErrorSanitizationLevel {
    /// Full details (for internal logging only)
    Full,
    /// User-safe (for user-facing messages)
    UserSafe,
    /// Minimal (for external/untrusted contexts)
    Minimal,
}

/// Sanitize error message based on context and security level
///
/// # Security Considerations
/// - Removes file paths that could reveal system structure
/// - Removes internal implementation details
/// - Prevents timing attack information leakage
/// - Maintains useful information for legitimate debugging
pub fn sanitize_error_message(
    error: &dyn std::error::Error,
    level: ErrorSanitizationLevel,
) -> String {
    let error_msg = error.to_string();

    match level {
        ErrorSanitizationLevel::Full => {
            // Full error for internal logging - but still sanitize sensitive paths
            sanitize_paths_in_message(&error_msg)
        }
        ErrorSanitizationLevel::UserSafe => {
            // User-safe version with generic messages
            match classify_error(&error_msg) {
                ErrorClass::FileSystem => "File operation failed".to_string(),
                ErrorClass::Network => "Network operation failed".to_string(),
                ErrorClass::Crypto => "Cryptographic operation failed".to_string(),
                ErrorClass::Authentication => "Authentication failed".to_string(),
                ErrorClass::Permission => "Access denied".to_string(),
                ErrorClass::Input => "Invalid input provided".to_string(),
                ErrorClass::Internal => "Internal error occurred".to_string(),
                ErrorClass::Unknown => "Operation failed".to_string(),
            }
        }
        ErrorSanitizationLevel::Minimal => {
            // Minimal information for external contexts
            "Operation failed".to_string()
        }
    }
}

/// Error classification for sanitization
#[derive(Debug)]
enum ErrorClass {
    FileSystem,
    Network,
    Crypto,
    Authentication,
    Permission,
    Input,
    Internal,
    Unknown,
}

/// Classify error type based on error message content
fn classify_error(error_msg: &str) -> ErrorClass {
    let error_lower = error_msg.to_lowercase();

    if error_lower.contains("file")
        || error_lower.contains("directory")
        || error_lower.contains("path")
        || error_lower.contains("io error")
    {
        ErrorClass::FileSystem
    } else if error_lower.contains("network")
        || error_lower.contains("connection")
        || error_lower.contains("timeout")
        || error_lower.contains("dns")
    {
        ErrorClass::Network
    } else if error_lower.contains("encrypt")
        || error_lower.contains("decrypt")
        || error_lower.contains("crypto")
        || error_lower.contains("key")
        || error_lower.contains("cipher")
        || error_lower.contains("hash")
    {
        ErrorClass::Crypto
    } else if error_lower.contains("auth")
        || error_lower.contains("login")
        || error_lower.contains("password")
        || error_lower.contains("token")
    {
        ErrorClass::Authentication
    } else if error_lower.contains("permission")
        || error_lower.contains("access")
        || error_lower.contains("denied")
        || error_lower.contains("forbidden")
    {
        ErrorClass::Permission
    } else if error_lower.contains("invalid")
        || error_lower.contains("parse")
        || error_lower.contains("format")
        || error_lower.contains("validation")
    {
        ErrorClass::Input
    } else if error_lower.contains("internal")
        || error_lower.contains("panic")
        || error_lower.contains("assertion")
    {
        ErrorClass::Internal
    } else {
        ErrorClass::Unknown
    }
}

/// Sanitize file paths in error messages to prevent information disclosure
fn sanitize_paths_in_message(message: &str) -> String {
    use regex::Regex;

    // Regex to match common path patterns
    let path_patterns = [
        // Unix absolute paths
        r"/[a-zA-Z0-9_/.-]+",
        // Windows absolute paths
        r"[A-Za-z]:\\[a-zA-Z0-9_\\.-]+",
        // Home directory references
        r"~/[a-zA-Z0-9_/.-]+",
    ];

    let mut sanitized = message.to_string();

    for pattern in &path_patterns {
        if let Ok(re) = Regex::new(pattern) {
            sanitized = re.replace_all(&sanitized, "[PATH_REDACTED]").to_string();
        }
    }

    // Also remove common sensitive patterns
    let sensitive_patterns = [
        (r"user[a-zA-Z0-9_-]*", "[USER_REDACTED]"),
        (r"pass[a-zA-Z0-9_-]*", "[CREDENTIAL_REDACTED]"),
        (r"key[a-zA-Z0-9_-]*", "[KEY_REDACTED]"),
        (r"secret[a-zA-Z0-9_-]*", "[SECRET_REDACTED]"),
    ];

    for (pattern, replacement) in &sensitive_patterns {
        if let Ok(re) = Regex::new(pattern) {
            sanitized = re.replace_all(&sanitized, *replacement).to_string();
        }
    }

    sanitized
}

/// Log security event with appropriate sanitization
pub fn log_security_event(event_type: &str, message: &str, error: Option<&dyn std::error::Error>) {
    let sanitized_message = sanitize_paths_in_message(message);

    if let Some(err) = error {
        let sanitized_error = sanitize_error_message(err, ErrorSanitizationLevel::Full);
        log::warn!(
            "SECURITY_EVENT: {} - {} - Error: {}",
            event_type,
            sanitized_message,
            sanitized_error
        );
    } else {
        log::warn!("SECURITY_EVENT: {} - {}", event_type, sanitized_message);
    }
}

/// Security-aware error formatter that prevents information leakage
pub struct SecureErrorFormatter {
    level: ErrorSanitizationLevel,
}

impl SecureErrorFormatter {
    pub fn new(level: ErrorSanitizationLevel) -> Self {
        Self { level }
    }

    pub fn format_error(&self, error: &dyn std::error::Error) -> String {
        sanitize_error_message(error, self.level)
    }

    pub fn format_result<T, E>(&self, result: &Result<T, E>) -> String
    where
        E: std::error::Error,
    {
        match result {
            Ok(_) => "Operation successful".to_string(),
            Err(e) => self.format_error(e),
        }
    }
}

/// Secure error context for adding safe context to errors
pub struct SecureErrorContext {
    operation: String,
    context: String,
}

impl SecureErrorContext {
    pub fn new(operation: &str) -> Self {
        Self {
            operation: operation.to_string(),
            context: String::new(),
        }
    }

    pub fn with_context(mut self, context: &str) -> Self {
        self.context = sanitize_paths_in_message(context);
        self
    }

    pub fn wrap_error<E>(&self, error: E) -> SecureContextError<E>
    where
        E: std::error::Error,
    {
        SecureContextError {
            operation: self.operation.clone(),
            context: self.context.clone(),
            source: error,
        }
    }
}

/// Error with secure context information
#[derive(Debug)]
pub struct SecureContextError<E> {
    operation: String,
    context: String,
    source: E,
}

impl<E> fmt::Display for SecureContextError<E>
where
    E: fmt::Display,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.context.is_empty() {
            write!(f, "Operation '{}' failed: {}", self.operation, self.source)
        } else {
            write!(
                f,
                "Operation '{}' failed in context '{}': {}",
                self.operation, self.context, self.source
            )
        }
    }
}

impl<E> std::error::Error for SecureContextError<E>
where
    E: std::error::Error + 'static,
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

/// Timing-safe error responses to prevent timing attacks
pub struct TimingSafeErrorResponse;

impl TimingSafeErrorResponse {
    /// Create a timing-safe error response with consistent delay
    pub async fn create_response(error: SecurityError) -> String {
        // Add small random delay to prevent timing analysis
        use rand::Rng;
        use tokio::time::{Duration, sleep};

        let delay_ms = rand::rng().random_range(10..50);
        sleep(Duration::from_millis(delay_ms)).await;

        match error {
            SecurityError::AuthenticationFailed => "Authentication failed".to_string(),
            SecurityError::AccessDenied => "Access denied".to_string(),
            _ => "Operation failed".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;

    #[test]
    fn test_sanitize_error_message_full() {
        let error = io::Error::new(
            io::ErrorKind::NotFound,
            "File /home/user/secret.txt not found",
        );
        let sanitized = sanitize_error_message(&error, ErrorSanitizationLevel::Full);
        assert!(sanitized.contains("[PATH_REDACTED]"));
        assert!(!sanitized.contains("/home/user/secret.txt"));
    }

    #[test]
    fn test_sanitize_error_message_user_safe() {
        let error = io::Error::new(io::ErrorKind::PermissionDenied, "Permission denied");
        let sanitized = sanitize_error_message(&error, ErrorSanitizationLevel::UserSafe);
        assert_eq!(sanitized, "Access denied");
    }

    #[test]
    fn test_sanitize_error_message_minimal() {
        let error = io::Error::other("Complex internal error with details");
        let sanitized = sanitize_error_message(&error, ErrorSanitizationLevel::Minimal);
        assert_eq!(sanitized, "Operation failed");
    }

    #[test]
    fn test_classify_error() {
        assert!(matches!(
            classify_error("file not found"),
            ErrorClass::FileSystem
        ));
        assert!(matches!(
            classify_error("encryption failed"),
            ErrorClass::Crypto
        ));
        assert!(matches!(
            classify_error("authentication error"),
            ErrorClass::Authentication
        ));
        assert!(matches!(
            classify_error("permission denied"),
            ErrorClass::Permission
        ));
    }

    #[test]
    fn test_sanitize_paths_in_message() {
        let message = "Failed to read /home/user/vault.db and C:\\Users\\user\\secret.txt";
        let sanitized = sanitize_paths_in_message(message);
        assert!(sanitized.contains("[PATH_REDACTED]"));
        assert!(!sanitized.contains("/home/user/vault.db"));
        assert!(!sanitized.contains("C:\\Users\\user\\secret.txt"));
    }

    #[tokio::test]
    async fn test_timing_safe_error_response() {
        let start = std::time::Instant::now();
        let _response =
            TimingSafeErrorResponse::create_response(SecurityError::AuthenticationFailed).await;
        let elapsed = start.elapsed();

        // Should have some delay to prevent timing attacks
        assert!(elapsed.as_millis() >= 10);
    }
}
