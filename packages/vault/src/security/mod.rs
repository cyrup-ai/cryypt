//! Security validation and hardening module
//!
//! Provides comprehensive input validation, secure file operations, and security hardening
//! for all vault operations. This module implements defense-in-depth security practices.

pub mod audit_logging;
pub mod error_handling;
pub mod input_validation;
pub mod secure_file_ops;

pub use audit_logging::{
    AuditLogger, SecurityEvent, SecuritySeverity, audit_authentication_attempt,
    audit_security_violation, audit_vault_operation,
};
pub use error_handling::{SecurityError, log_security_event, sanitize_error_message};
pub use input_validation::{
    SecurityValidationError, validate_file_size, validate_key_version, validate_keychain_namespace,
    validate_vault_path,
};
pub use secure_file_ops::{
    AtomicFileWriter, ProductionSecureFileOps, SecureFileOperations, SecureTempFile,
};
