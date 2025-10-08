//! Production-grade structured logging infrastructure
//!
//! Provides env_logger-based logging with secure handling of sensitive data
//! and proper integration with the standard log crate.

use log::{debug, error, info, warn};
use sha2::{Digest, Sha256};
use std::sync::Once;
use std::time::Duration;

static INIT_LOGGER: Once = Once::new();

/// Production logging infrastructure using `env_logger`
pub struct LoggingTransformer;

impl LoggingTransformer {
    /// Initialize logging system (should be called once at application startup)
    ///
    /// This sets up `env_logger` with production-ready configuration.
    /// Configure logging levels via `RUST_LOG` environment variable:
    /// - `RUST_LOG=debug` - Enable all debug logs
    /// - `RUST_LOG=info` - Enable info and above (recommended for production)  
    /// - `RUST_LOG=error` - Only errors
    /// - `RUST_LOG=cryypt_vault=debug,cryypt_quic=info` - Module-specific levels
    pub fn init() {
        INIT_LOGGER.call_once(|| {
            env_logger::Builder::from_default_env()
                .format_timestamp_micros()
                .init();

            info!("🔧 Structured logging initialized");
        });
    }

    /// Initialize logging for test environments
    ///
    /// Use this in test modules to avoid initialization conflicts
    pub fn init_test() {
        let _ = env_logger::Builder::from_default_env()
            .is_test(true)
            .try_init();
    }

    /// Log RPC operations with structured data
    pub fn log_rpc_call(server_addr: &str, pool_size: usize, timeout: Duration) {
        info!("Creating RPC call to {server_addr} (pool_size: {pool_size}, timeout: {timeout:?})");
    }

    /// Log messaging operations with message metadata
    pub fn log_messaging_info(operation: &str, message_len: usize) {
        debug!("Messaging operation: {operation} (message_len: {message_len})");
    }

    /// Log server startup events
    pub fn log_server_startup(protocol: &str, port: u16) {
        info!("🚀 {protocol} server listening on port {port}");
    }

    /// Log vault operations with secure key handling
    ///
    /// Sensitive keys are hashed using SHA-256 for secure logging
    pub fn log_vault_operation(operation: &str, key: &str, success: bool) {
        let key_hash = Self::secure_hash_key(key);
        if success {
            info!("Vault operation succeeded: {operation} (key_hash: {key_hash})");
        } else {
            warn!("Vault operation failed: {operation} (key_hash: {key_hash})");
        }
    }

    /// Log terminal and UI setup events  
    pub fn log_terminal_setup(event: &str, details: Option<&str>) {
        match details {
            Some(details) => info!("Terminal setup: {event} - {details}"),
            None => info!("Terminal setup: {event}"),
        }
    }

    /// Secure logging of cryptographic errors
    ///
    /// Logs error types without exposing sensitive data
    pub fn log_crypto_error(operation: &str, error: &dyn std::error::Error) {
        error!(
            "Cryptographic operation failed: {} (error_type: {})",
            operation,
            std::any::type_name_of_val(error)
        );
    }

    /// Log authentication events securely
    ///
    /// User identifiers are hashed for privacy while maintaining traceability
    pub fn log_auth_event(event: &str, user_id: Option<&str>, success: bool) {
        if success {
            let user_hash = user_id.map_or_else(|| "anonymous".to_string(), Self::secure_hash_key);
            info!("Authentication succeeded: {event} (user_hash: {user_hash})");
        } else {
            warn!("Authentication failed: {event}");
        }
    }

    /// Log cleanup and shutdown events with error context
    pub fn log_cleanup_warning(component: &str, error: &dyn std::error::Error) {
        warn!(
            "Component cleanup failed: {} (error_type: {})",
            component,
            std::any::type_name_of_val(error)
        );
    }

    /// Log performance metrics and timing information
    pub fn log_performance_metric(operation: &str, duration_ms: u64, success: bool) {
        if success {
            debug!("Performance: {operation} completed in {duration_ms}ms");
        } else {
            warn!("Performance: {operation} failed after {duration_ms}ms");
        }
    }

    /// Log network operations with connection details
    pub fn log_network_operation(
        operation: &str,
        remote_addr: &str,
        bytes_transferred: Option<usize>,
    ) {
        match bytes_transferred {
            Some(bytes) => debug!("Network: {operation} to {remote_addr} ({bytes} bytes)"),
            None => debug!("Network: {operation} to {remote_addr}"),
        }
    }

    /// Cryptographically secure key hashing for logging
    ///
    /// Uses SHA-256 instead of `DefaultHasher` for security.
    /// Returns first 12 characters of hex-encoded hash for readability.
    fn secure_hash_key(key: &str) -> String {
        let hash = Sha256::digest(key.as_bytes());
        let hex_hash = format!("{hash:x}");
        // Return first 12 chars for brevity while maintaining uniqueness
        format!("#{}", &hex_hash[..12])
    }
}

/// Convenience macro for logging operations with structured data
#[macro_export]
macro_rules! log_operation {
    (INFO, $operation:expr, $($field:ident = $value:expr),*) => {
        log::info!(
            "Operation: {} {}",
            $operation,
            format!("$(format!(\"{}={}\", stringify!($field), $value)),*")
        );
    };
    (WARN, $operation:expr, $($field:ident = $value:expr),*) => {
        log::warn!(
            "Operation: {} {}",
            $operation,
            format!("$(format!(\"{}={}\", stringify!($field), $value)),*")
        );
    };
    (ERROR, $operation:expr, $($field:ident = $value:expr),*) => {
        log::error!(
            "Operation: {} {}",
            $operation,
            format!("$(format!(\"{}={}\", stringify!($field), $value)),*")
        );
    };
}

/// Macro for secure cryptographic operation logging
#[macro_export]
macro_rules! log_crypto_safe {
    (ERROR, $operation:expr, $error:expr) => {
        log::error!(
            "Cryptographic operation failed: {} (error_type: {})",
            $operation,
            std::any::type_name_of_val(&$error)
        );
    };
    (WARN, $operation:expr, $error:expr) => {
        log::warn!(
            "Cryptographic operation warning: {} (error_type: {})",
            $operation,
            std::any::type_name_of_val(&$error)
        );
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_key_hashing() {
        LoggingTransformer::init_test();

        let key1 = "sensitive_key_123";
        let key2 = "different_key_456";

        let hash1 = LoggingTransformer::secure_hash_key(key1);
        let hash2 = LoggingTransformer::secure_hash_key(key2);

        // Hashes should be different
        assert_ne!(hash1, hash2);

        // Hash should be consistent
        let hash1_again = LoggingTransformer::secure_hash_key(key1);
        assert_eq!(hash1, hash1_again);

        // Hash should start with # and be 13 chars total
        assert!(hash1.starts_with('#'));
        assert_eq!(hash1.len(), 13);
    }

    #[test]
    fn test_logging_operations() {
        LoggingTransformer::init_test();

        // These should not panic and should produce log output
        LoggingTransformer::log_vault_operation("get", "test_key", true);
        LoggingTransformer::log_auth_event("login", Some("user123"), true);
        LoggingTransformer::log_server_startup("QUIC", 8443);
        LoggingTransformer::log_performance_metric("encryption", 150, true);
    }
}
