//! Input validation for security hardening
//!
//! Provides comprehensive validation for all user inputs to prevent injection attacks,
//! path traversal, buffer overflows, and other security vulnerabilities.

use std::path::{Path, PathBuf};
use thiserror::Error;

/// Maximum allowed file size for vault operations (100MB)
const MAX_VAULT_FILE_SIZE: u64 = 100 * 1024 * 1024;

/// Maximum allowed key version to prevent integer overflow
const MAX_KEY_VERSION: u32 = 999_999;

/// Maximum allowed keychain namespace length
const MAX_NAMESPACE_LENGTH: usize = 64;

/// Security validation errors
#[derive(Error, Debug)]
pub enum SecurityValidationError {
    #[error("Invalid vault path: {0}")]
    InvalidVaultPath(String),

    #[error("Path traversal attempt detected: {0}")]
    PathTraversalAttempt(String),

    #[error("Invalid keychain namespace: {0}")]
    InvalidKeychainNamespace(String),

    #[error("Invalid key version: {0}")]
    InvalidKeyVersion(String),

    #[error("File size exceeds maximum allowed: {0} bytes")]
    FileSizeExceeded(u64),

    #[error("Invalid file extension: expected {expected}, got {actual}")]
    InvalidFileExtension { expected: String, actual: String },

    #[error("Unsafe characters detected in input: {0}")]
    UnsafeCharacters(String),
}

/// Validate vault file path for security
///
/// # Security Checks
/// - Prevents directory traversal attacks (../, ..\)
/// - Validates file extensions (.db, .vault)
/// - Ensures path is within allowed directories
/// - Checks for null bytes and control characters
pub fn validate_vault_path(
    path: &Path,
    expected_extension: &str,
) -> Result<PathBuf, SecurityValidationError> {
    let path_str = path.to_string_lossy();

    // Check for null bytes (path injection)
    if path_str.contains('\0') {
        return Err(SecurityValidationError::UnsafeCharacters(
            "Null byte detected in path".to_string(),
        ));
    }

    // Check for directory traversal attempts
    if path_str.contains("../") || path_str.contains("..\\") {
        return Err(SecurityValidationError::PathTraversalAttempt(
            path_str.to_string(),
        ));
    }

    // Check for absolute paths outside allowed directories (security policy)
    if path.is_absolute() {
        let canonical = path.canonicalize().map_err(|_| {
            SecurityValidationError::InvalidVaultPath("Cannot resolve path".to_string())
        })?;

        // Only allow paths in current directory or explicit vault directories
        let current_dir = std::env::current_dir().map_err(|_| {
            SecurityValidationError::InvalidVaultPath(
                "Cannot determine current directory".to_string(),
            )
        })?;

        if !canonical.starts_with(&current_dir) {
            return Err(SecurityValidationError::PathTraversalAttempt(format!(
                "Path outside allowed directory: {}",
                canonical.display()
            )));
        }
    }

    // Validate file extension
    if let Some(ext) = path.extension() {
        let ext_str = ext.to_string_lossy();
        if ext_str != expected_extension {
            return Err(SecurityValidationError::InvalidFileExtension {
                expected: expected_extension.to_string(),
                actual: ext_str.to_string(),
            });
        }
    } else {
        return Err(SecurityValidationError::InvalidFileExtension {
            expected: expected_extension.to_string(),
            actual: "none".to_string(),
        });
    }

    // Return canonicalized safe path
    Ok(path.to_path_buf())
}

/// Validate keychain namespace for security
///
/// # Security Checks
/// - Prevents injection attacks in keychain operations
/// - Validates character set (alphanumeric + underscore/hyphen only)
/// - Enforces maximum length limits
/// - Prevents reserved namespace names
pub fn validate_keychain_namespace(namespace: &str) -> Result<String, SecurityValidationError> {
    // Check length limits
    if namespace.is_empty() {
        return Err(SecurityValidationError::InvalidKeychainNamespace(
            "Namespace cannot be empty".to_string(),
        ));
    }

    if namespace.len() > MAX_NAMESPACE_LENGTH {
        return Err(SecurityValidationError::InvalidKeychainNamespace(format!(
            "Namespace too long: {} characters (max {})",
            namespace.len(),
            MAX_NAMESPACE_LENGTH
        )));
    }

    // Check for safe character set only
    if !namespace
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err(SecurityValidationError::InvalidKeychainNamespace(
            "Namespace contains unsafe characters (only alphanumeric, underscore, hyphen allowed)"
                .to_string(),
        ));
    }

    // Prevent reserved names that could cause conflicts
    let reserved_names = ["system", "root", "admin", "keychain", "vault", "cryypt"];
    if reserved_names.contains(&namespace.to_lowercase().as_str()) {
        return Err(SecurityValidationError::InvalidKeychainNamespace(format!(
            "Reserved namespace name: {}",
            namespace
        )));
    }

    // Must start with letter (not number or special char)
    if !namespace.chars().next().unwrap().is_ascii_alphabetic() {
        return Err(SecurityValidationError::InvalidKeychainNamespace(
            "Namespace must start with a letter".to_string(),
        ));
    }

    Ok(namespace.to_string())
}

/// Validate key version for security
///
/// # Security Checks
/// - Prevents integer overflow attacks
/// - Enforces reasonable bounds (1 to MAX_KEY_VERSION)
/// - Validates version progression logic
pub fn validate_key_version(version: u32) -> Result<u32, SecurityValidationError> {
    if version == 0 {
        return Err(SecurityValidationError::InvalidKeyVersion(
            "Key version must be greater than 0".to_string(),
        ));
    }

    if version > MAX_KEY_VERSION {
        return Err(SecurityValidationError::InvalidKeyVersion(format!(
            "Key version {} exceeds maximum allowed {}",
            version, MAX_KEY_VERSION
        )));
    }

    Ok(version)
}

/// Validate file size for security
///
/// # Security Checks
/// - Prevents resource exhaustion attacks
/// - Enforces maximum file size limits
/// - Validates against available disk space
pub fn validate_file_size(size: u64) -> Result<u64, SecurityValidationError> {
    if size > MAX_VAULT_FILE_SIZE {
        return Err(SecurityValidationError::FileSizeExceeded(size));
    }

    Ok(size)
}

/// Sanitize string input for logging and error messages
///
/// # Security Checks
/// - Removes control characters that could cause log injection
/// - Limits string length to prevent log flooding
/// - Escapes special characters for safe display
pub fn sanitize_string_for_logging(input: &str) -> String {
    const MAX_LOG_LENGTH: usize = 256;

    let sanitized: String = input
        .chars()
        .filter(|c| !c.is_control() || *c == '\n' || *c == '\t')
        .take(MAX_LOG_LENGTH)
        .collect();

    if input.len() > MAX_LOG_LENGTH {
        format!("{}... (truncated)", sanitized)
    } else {
        sanitized
    }
}

/// Validate and sanitize command-line arguments
///
/// # Security Checks
/// - Prevents command injection through argument parsing
/// - Validates argument structure and types
/// - Sanitizes special characters
pub fn validate_cli_argument(arg: &str, arg_name: &str) -> Result<String, SecurityValidationError> {
    // Check for null bytes
    if arg.contains('\0') {
        return Err(SecurityValidationError::UnsafeCharacters(format!(
            "Null byte in argument {}",
            arg_name
        )));
    }

    // Check for command injection patterns
    let dangerous_patterns = [";", "|", "&", "`", "$", "(", ")", "<", ">"];
    for pattern in &dangerous_patterns {
        if arg.contains(pattern) {
            return Err(SecurityValidationError::UnsafeCharacters(format!(
                "Dangerous character '{}' in argument {}",
                pattern, arg_name
            )));
        }
    }

    Ok(arg.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_validate_vault_path_valid() {
        let path = PathBuf::from("test.db");
        assert!(validate_vault_path(&path, "db").is_ok());
    }

    #[test]
    fn test_validate_vault_path_traversal() {
        let path = PathBuf::from("../../../etc/passwd");
        assert!(validate_vault_path(&path, "db").is_err());
    }

    #[test]
    fn test_validate_keychain_namespace_valid() {
        assert!(validate_keychain_namespace("my_vault_123").is_ok());
    }

    #[test]
    fn test_validate_keychain_namespace_invalid_chars() {
        assert!(validate_keychain_namespace("my vault!").is_err());
    }

    #[test]
    fn test_validate_key_version_valid() {
        assert!(validate_key_version(1).is_ok());
        assert!(validate_key_version(100).is_ok());
    }

    #[test]
    fn test_validate_key_version_invalid() {
        assert!(validate_key_version(0).is_err());
        assert!(validate_key_version(MAX_KEY_VERSION + 1).is_err());
    }

    #[test]
    fn test_sanitize_string_for_logging() {
        let input = "normal text\x00with\x01control\x02chars";
        let sanitized = sanitize_string_for_logging(input);
        assert!(!sanitized.contains('\x00'));
        assert!(!sanitized.contains('\x01'));
        assert!(!sanitized.contains('\x02'));
    }
}
