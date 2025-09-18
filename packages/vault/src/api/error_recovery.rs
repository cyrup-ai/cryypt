//! Production-ready error recovery with proper error categorization

use crate::error::VaultError;
use std::future::Future;
use std::time::Duration;
use tracing::{debug, error, warn};

/// Retry policy configuration for different error types
#[derive(Debug, Clone)]
pub struct RetryPolicy {
    pub max_attempts: u32,
    pub base_delay: Duration,
    pub max_delay: Duration,
    pub backoff_multiplier: f64,
    pub jitter: bool,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            base_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(30),
            backoff_multiplier: 2.0,
            jitter: true,
        }
    }
}

/// Circuit breaker states for cascading failure protection
#[derive(Debug, Clone, PartialEq)]
pub enum CircuitState {
    Closed,
    Open,
    HalfOpen,
}

/// Production-ready error recovery with proper error categorization
pub struct ErrorRecovery {
    network_policy: RetryPolicy,
    database_policy: RetryPolicy,
    system_policy: RetryPolicy,
    _circuit_failure_threshold: u32,
    _circuit_recovery_timeout: Duration,
}

impl ErrorRecovery {
    /// Create new error recovery with comprehensive policies
    pub fn new() -> Self {
        Self {
            network_policy: RetryPolicy {
                max_attempts: 5,
                base_delay: Duration::from_millis(200),
                max_delay: Duration::from_secs(10),
                backoff_multiplier: 2.0,
                jitter: true,
            },
            database_policy: RetryPolicy {
                max_attempts: 3,
                base_delay: Duration::from_millis(100),
                max_delay: Duration::from_secs(5),
                backoff_multiplier: 1.5,
                jitter: true,
            },
            system_policy: RetryPolicy {
                max_attempts: 2,
                base_delay: Duration::from_secs(1),
                max_delay: Duration::from_secs(60),
                backoff_multiplier: 3.0,
                jitter: true,
            },
            _circuit_failure_threshold: 5,
            _circuit_recovery_timeout: Duration::from_secs(30),
        }
    }

    /// Create production-optimized configuration
    pub fn production_optimized() -> Self {
        Self {
            network_policy: RetryPolicy {
                max_attempts: 3,
                base_delay: Duration::from_millis(100),
                max_delay: Duration::from_secs(5),
                backoff_multiplier: 2.0,
                jitter: true,
            },
            database_policy: RetryPolicy {
                max_attempts: 2,
                base_delay: Duration::from_millis(50),
                max_delay: Duration::from_secs(2),
                backoff_multiplier: 1.5,
                jitter: true,
            },
            system_policy: RetryPolicy {
                max_attempts: 1,
                base_delay: Duration::from_millis(500),
                max_delay: Duration::from_secs(30),
                backoff_multiplier: 2.0,
                jitter: false,
            },
            _circuit_failure_threshold: 3,
            _circuit_recovery_timeout: Duration::from_secs(15),
        }
    }

    /// Check if error is retryable based on comprehensive categorization
    pub fn is_retryable(&self, error: &VaultError) -> bool {
        match error {
            // Network Errors (Retryable)
            VaultError::TimeoutError(_) => true,

            // Database Errors (Mixed)
            VaultError::Database(db_err) => self.is_database_error_retryable(db_err),
            VaultError::DatabaseError(msg) => self.is_database_message_retryable(msg),

            // Authentication Errors (Permanent)
            VaultError::InvalidPassphrase => false,
            VaultError::WeakPassphrase => false,
            VaultError::VaultLocked => false,
            VaultError::AuthenticationFailed(_) => false,

            // Validation Errors (Permanent)
            VaultError::InvalidInput(_) => false,
            VaultError::InvalidPattern(_) => false,
            VaultError::ValueType(_) => false,
            VaultError::Configuration(_) => false,
            VaultError::UnsupportedOperation(_) => false,
            VaultError::Conflict(_) => false,

            // System Errors (Mixed)
            VaultError::Io(io_err) => self.is_io_error_retryable(io_err),
            VaultError::MemoryProtection(_) => true, // May recover after cleanup
            VaultError::MemoryCorruption => false,   // Permanent corruption

            // Crypto/Key Errors (Mixed)
            VaultError::Encryption(_) => false, // Likely permanent data/key issue
            VaultError::Decryption(_) => false, // Likely permanent data/key issue
            VaultError::KeyDerivation(_) => false, // Likely permanent parameter issue
            VaultError::InvalidKey(_) => false, // Permanent key issue
            VaultError::KeyRotation(_) => true, // May succeed after timing
            VaultError::Crypto(_) => false,     // Generally permanent

            // Operational Errors (Mixed)
            VaultError::ItemNotFound => false, // Permanent - item doesn't exist
            VaultError::TooManyAttempts(_) => true, // Retryable after cooldown
            VaultError::Migration(_) => false, // Permanent schema issue
            VaultError::Provider(_) => true,   // May recover

            // Time/Serialization Errors (Permanent)
            VaultError::Time(_) => false,
            VaultError::Serialization(_) => false,

            // Generic Errors (Conservative - not retryable)
            VaultError::Internal(_) => false,
            VaultError::Other(_) => false,
        }
    }

    /// Determine if database error is retryable
    fn is_database_error_retryable(&self, db_err: &surrealdb::Error) -> bool {
        // For SurrealDB 3.0, we'll check the error message since the error structure has changed
        let error_msg = db_err.to_string().to_lowercase();

        // Retryable patterns in error messages
        error_msg.contains("transaction")
            || error_msg.contains("timeout")
            || error_msg.contains("conflict")
            || error_msg.contains("connection")
            || error_msg.contains("unavailable")
            || error_msg.contains("ws")
            || error_msg.contains("http")
    }

    /// Determine if database error message indicates retryable condition
    fn is_database_message_retryable(&self, msg: &str) -> bool {
        let msg_lower = msg.to_lowercase();

        // Retryable patterns
        if msg_lower.contains("timeout")
            || msg_lower.contains("connection")
            || msg_lower.contains("unavailable")
            || msg_lower.contains("busy")
            || msg_lower.contains("lock")
            || msg_lower.contains("retry")
        {
            return true;
        }

        // Permanent failure patterns
        if msg_lower.contains("constraint")
            || msg_lower.contains("unique")
            || msg_lower.contains("invalid")
            || msg_lower.contains("not found")
            || msg_lower.contains("permission")
            || msg_lower.contains("schema")
        {
            return false;
        }

        // Conservative default
        false
    }

    /// Determine if IO error is retryable
    fn is_io_error_retryable(&self, io_err: &std::io::Error) -> bool {
        use std::io::ErrorKind;

        match io_err.kind() {
            ErrorKind::TimedOut => true,
            ErrorKind::Interrupted => true,
            ErrorKind::ConnectionRefused => true,
            ErrorKind::ConnectionReset => true,
            ErrorKind::ConnectionAborted => true,
            ErrorKind::WouldBlock => true,
            ErrorKind::UnexpectedEof => true,

            // Permanent failures
            ErrorKind::NotFound => false,
            ErrorKind::PermissionDenied => false,
            ErrorKind::InvalidData => false,
            ErrorKind::InvalidInput => false,
            ErrorKind::AlreadyExists => false,

            _ => false, // Conservative default
        }
    }

    /// Get appropriate retry policy for error type
    pub fn get_retry_policy(&self, error: &VaultError) -> &RetryPolicy {
        match error {
            VaultError::TimeoutError(_) => &self.network_policy,
            VaultError::Database(_) | VaultError::DatabaseError(_) => &self.database_policy,
            VaultError::Io(_) | VaultError::MemoryProtection(_) | VaultError::Provider(_) => {
                &self.system_policy
            }
            _ => &self.database_policy, // Use database policy as default
        }
    }

    /// Execute operation with comprehensive retry logic and error categorization
    pub async fn retry_with_policy<F, T, Fut>(
        &self,
        operation: F,
        policy: &RetryPolicy,
    ) -> Result<T, VaultError>
    where
        F: Fn() -> Fut,
        Fut: Future<Output = Result<T, VaultError>>,
    {
        let mut attempts = 0;
        let mut delay = policy.base_delay;

        loop {
            match operation().await {
                Ok(result) => {
                    if attempts > 0 {
                        debug!("Operation succeeded after {} attempts", attempts + 1);
                    }
                    return Ok(result);
                }
                Err(error) => {
                    attempts += 1;

                    // Check if error is retryable
                    if !self.is_retryable(&error) {
                        warn!("Non-retryable error encountered: {}", error);
                        return Err(error);
                    }

                    // Check retry limit
                    if attempts >= policy.max_attempts {
                        error!(
                            "Max retry attempts ({}) exceeded for error: {}",
                            policy.max_attempts, error
                        );
                        return Err(error);
                    }

                    // Calculate delay with jitter
                    let actual_delay = if policy.jitter {
                        let jitter_range = delay.as_millis() as u64 / 4;
                        let jitter = fastrand::u64(0..=jitter_range);
                        delay + Duration::from_millis(jitter)
                    } else {
                        delay
                    };

                    debug!(
                        "Retrying operation (attempt {}/{}) after {:?} delay: {}",
                        attempts + 1,
                        policy.max_attempts,
                        actual_delay,
                        error
                    );

                    // Apply backoff delay
                    tokio::time::sleep(actual_delay).await;

                    // Update delay for next attempt
                    delay = Duration::from_millis(
                        ((delay.as_millis() as f64) * policy.backoff_multiplier) as u64,
                    )
                    .min(policy.max_delay);
                }
            }
        }
    }

    /// Convenience method for retrying vault operations with appropriate policy
    pub async fn retry_vault_operation<F, T, Fut>(&self, operation: F) -> Result<T, VaultError>
    where
        F: Fn() -> Fut,
        Fut: Future<Output = Result<T, VaultError>>,
    {
        // Try operation once to determine error type and policy
        match operation().await {
            Ok(result) => Ok(result),
            Err(error) => {
                let policy = self.get_retry_policy(&error);
                if self.is_retryable(&error) {
                    // Use the appropriate retry policy
                    self.retry_with_policy(operation, policy).await
                } else {
                    Err(error)
                }
            }
        }
    }
}

impl Default for ErrorRecovery {
    fn default() -> Self {
        Self::new()
    }
}
