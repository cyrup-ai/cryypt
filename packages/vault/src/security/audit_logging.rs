//! Security audit logging module
//!
//! Provides comprehensive audit logging for all security-sensitive operations
//! with tamper-evident logging and structured security event tracking.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// Security event types for audit logging
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecurityEvent {
    /// Authentication events
    AuthenticationAttempt {
        success: bool,
        method: String,
        user_context: String,
    },

    /// Vault operations
    VaultOperation {
        operation: String,
        vault_path: String,
        success: bool,
    },

    /// Key management events
    KeyOperation {
        operation: String,
        key_namespace: String,
        key_version: u32,
        success: bool,
    },

    /// File system operations
    FileSystemOperation {
        operation: String,
        file_type: String,
        success: bool,
    },

    /// Cryptographic operations
    CryptographicOperation {
        operation: String,
        algorithm: String,
        success: bool,
    },

    /// Security violations
    SecurityViolation {
        violation_type: String,
        severity: SecuritySeverity,
        details: String,
    },

    /// Rate limiting events
    RateLimitEvent {
        operation: String,
        limit_exceeded: bool,
        current_rate: u32,
    },

    /// Access control events
    AccessControlEvent {
        resource: String,
        action: String,
        granted: bool,
        reason: String,
    },
}

/// Security event severity levels
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecuritySeverity {
    Low,
    Medium,
    High,
    Critical,
}

/// Audit log entry with tamper-evident properties
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLogEntry {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub event: SecurityEvent,
    pub session_id: Option<String>,
    pub client_info: ClientInfo,
    pub metadata: HashMap<String, String>,
    pub checksum: String,
}

/// Client information for audit context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientInfo {
    pub process_id: u32,
    pub executable_path: String,
    pub working_directory: String,
    pub environment_hash: String,
}

/// Audit logger with security features
pub struct AuditLogger {
    session_id: String,
    client_info: ClientInfo,
}

impl AuditLogger {
    /// Create new audit logger for current session
    pub fn new() -> Self {
        let session_id = Uuid::new_v4().to_string();
        let client_info = Self::collect_client_info();

        Self {
            session_id,
            client_info,
        }
    }

    /// Log security event with full audit trail
    pub async fn log_event(&self, event: SecurityEvent, metadata: Option<HashMap<String, String>>) {
        let entry = self.create_audit_entry(event, metadata).await;
        self.write_audit_entry(&entry).await;

        // Also log to standard logging system
        self.log_to_standard_logger(&entry);
    }

    /// Create tamper-evident audit entry
    async fn create_audit_entry(
        &self,
        event: SecurityEvent,
        metadata: Option<HashMap<String, String>>,
    ) -> AuditLogEntry {
        let id = Uuid::new_v4();
        let timestamp = Utc::now();
        let metadata = metadata.unwrap_or_default();

        // Create entry without checksum first
        let mut entry = AuditLogEntry {
            id,
            timestamp,
            event,
            session_id: Some(self.session_id.clone()),
            client_info: self.client_info.clone(),
            metadata,
            checksum: String::new(),
        };

        // Calculate tamper-evident checksum
        entry.checksum = self.calculate_entry_checksum(&entry).await;

        entry
    }

    /// Calculate tamper-evident checksum for audit entry
    async fn calculate_entry_checksum(&self, entry: &AuditLogEntry) -> String {
        use sha2::{Digest, Sha256};

        // Serialize entry without checksum for hashing
        let mut entry_for_hash = entry.clone();
        entry_for_hash.checksum = String::new();

        let serialized = serde_json::to_string(&entry_for_hash)
            .unwrap_or_else(|_| "SERIALIZATION_ERROR".to_string());

        let mut hasher = Sha256::new();
        hasher.update(serialized.as_bytes());
        hasher.update(self.session_id.as_bytes()); // Include session context

        format!("{:x}", hasher.finalize())
    }

    /// Write audit entry to secure audit log
    async fn write_audit_entry(&self, entry: &AuditLogEntry) {
        // In production, this would write to a secure, append-only audit log
        // For now, we'll use structured logging
        let json_entry = serde_json::to_string(entry)
            .unwrap_or_else(|_| "AUDIT_SERIALIZATION_ERROR".to_string());

        log::info!(target: "SECURITY_AUDIT", "{}", json_entry);
    }

    /// Log to standard logger with appropriate level
    fn log_to_standard_logger(&self, entry: &AuditLogEntry) {
        let event_summary = self.format_event_summary(&entry.event);

        match &entry.event {
            SecurityEvent::SecurityViolation { severity, .. } => match severity {
                SecuritySeverity::Critical => log::error!("SECURITY: {}", event_summary),
                SecuritySeverity::High => log::warn!("SECURITY: {}", event_summary),
                SecuritySeverity::Medium => log::info!("SECURITY: {}", event_summary),
                SecuritySeverity::Low => log::debug!("SECURITY: {}", event_summary),
            },
            SecurityEvent::AuthenticationAttempt { success: false, .. } => {
                log::warn!("SECURITY: {}", event_summary);
            }
            _ => {
                log::info!("SECURITY: {}", event_summary);
            }
        }
    }

    /// Format event summary for logging
    fn format_event_summary(&self, event: &SecurityEvent) -> String {
        match event {
            SecurityEvent::AuthenticationAttempt {
                success, method, ..
            } => {
                format!(
                    "Authentication {} using {}",
                    if *success { "succeeded" } else { "failed" },
                    method
                )
            }
            SecurityEvent::VaultOperation {
                operation, success, ..
            } => {
                format!(
                    "Vault operation '{}' {}",
                    operation,
                    if *success { "succeeded" } else { "failed" }
                )
            }
            SecurityEvent::KeyOperation {
                operation,
                key_namespace,
                success,
                ..
            } => {
                format!(
                    "Key operation '{}' on namespace '{}' {}",
                    operation,
                    key_namespace,
                    if *success { "succeeded" } else { "failed" }
                )
            }
            SecurityEvent::SecurityViolation {
                violation_type,
                severity,
                ..
            } => {
                format!(
                    "Security violation: {} (severity: {:?})",
                    violation_type, severity
                )
            }
            SecurityEvent::RateLimitEvent {
                operation,
                limit_exceeded,
                current_rate,
            } => {
                format!(
                    "Rate limit for '{}': {} (rate: {})",
                    operation,
                    if *limit_exceeded {
                        "exceeded"
                    } else {
                        "within limits"
                    },
                    current_rate
                )
            }
            SecurityEvent::AccessControlEvent {
                resource,
                action,
                granted,
                ..
            } => {
                format!(
                    "Access to '{}' for action '{}': {}",
                    resource,
                    action,
                    if *granted { "granted" } else { "denied" }
                )
            }
            SecurityEvent::FileSystemOperation {
                operation,
                file_type,
                success,
            } => {
                format!(
                    "File operation '{}' on {} {}",
                    operation,
                    file_type,
                    if *success { "succeeded" } else { "failed" }
                )
            }
            SecurityEvent::CryptographicOperation {
                operation,
                algorithm,
                success,
            } => {
                format!(
                    "Crypto operation '{}' using {} {}",
                    operation,
                    algorithm,
                    if *success { "succeeded" } else { "failed" }
                )
            }
        }
    }

    /// Collect client information for audit context
    fn collect_client_info() -> ClientInfo {
        use sha2::{Digest, Sha256};

        let process_id = std::process::id();

        let executable_path = std::env::current_exe()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| "UNKNOWN_EXECUTABLE".to_string());

        let working_directory = std::env::current_dir()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| "UNKNOWN_DIRECTORY".to_string());

        // Create environment hash (for tamper detection)
        let mut hasher = Sha256::new();
        let mut env_vars: Vec<_> = std::env::vars().collect();
        env_vars.sort(); // Deterministic ordering

        for (key, value) in env_vars {
            // Only hash non-sensitive environment variables
            if !key.to_lowercase().contains("secret")
                && !key.to_lowercase().contains("password")
                && !key.to_lowercase().contains("token")
            {
                hasher.update(format!("{}={}", key, value).as_bytes());
            }
        }

        let environment_hash = format!("{:x}", hasher.finalize());

        ClientInfo {
            process_id,
            executable_path,
            working_directory,
            environment_hash,
        }
    }
}

impl Default for AuditLogger {
    fn default() -> Self {
        Self::new()
    }
}

/// Convenience function for auditing vault operations
pub async fn audit_vault_operation(
    operation: &str,
    vault_path: &str,
    success: bool,
    additional_metadata: Option<HashMap<String, String>>,
) {
    let logger = AuditLogger::new();
    let event = SecurityEvent::VaultOperation {
        operation: operation.to_string(),
        vault_path: vault_path.to_string(),
        success,
    };

    logger.log_event(event, additional_metadata).await;
}

/// Convenience function for auditing authentication attempts
pub async fn audit_authentication_attempt(method: &str, user_context: &str, success: bool) {
    let logger = AuditLogger::new();
    let event = SecurityEvent::AuthenticationAttempt {
        success,
        method: method.to_string(),
        user_context: user_context.to_string(),
    };

    logger.log_event(event, None).await;
}

/// Convenience function for auditing security violations
pub async fn audit_security_violation(
    violation_type: &str,
    severity: SecuritySeverity,
    details: &str,
) {
    let logger = AuditLogger::new();
    let event = SecurityEvent::SecurityViolation {
        violation_type: violation_type.to_string(),
        severity,
        details: details.to_string(),
    };

    logger.log_event(event, None).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_audit_logger_creation() {
        let logger = AuditLogger::new();
        assert!(!logger.session_id.is_empty());
        assert!(logger.client_info.process_id > 0);
    }

    #[tokio::test]
    async fn test_audit_entry_checksum() {
        let logger = AuditLogger::new();
        let event = SecurityEvent::VaultOperation {
            operation: "test".to_string(),
            vault_path: "test.db".to_string(),
            success: true,
        };

        let entry = logger.create_audit_entry(event, None).await;
        assert!(!entry.checksum.is_empty());
        assert_eq!(entry.checksum.len(), 64); // SHA256 hex length
    }

    #[tokio::test]
    async fn test_convenience_functions() {
        // These should not panic
        audit_vault_operation("test", "test.db", true, None).await;
        audit_authentication_attempt("password", "test_user", true).await;
        audit_security_violation("test_violation", SecuritySeverity::Low, "test details").await;
    }
}
