//! Key escaping and validation utilities for SurrealDB natural keys
//!
//! Provides functions to escape/unescape user keys for safe use as SurrealDB record IDs.

use crate::error::VaultError;

/// Escape a user key to be safe for use as a SurrealDB record ID
///
/// SurrealDB record IDs have specific character restrictions and escaping rules.
/// This function ensures user keys can be safely used as natural keys.
pub fn escape_key(key: &str) -> String {
    // SurrealDB uses backtick escaping for record IDs with special characters
    // Following the same logic as EscapeRid in SurrealDB source
    if key.contains(|x: char| !x.is_ascii_alphanumeric() && x != '_')
        || !key.contains(|x: char| !x.is_ascii_digit() && x != '_')
    {
        // Escape with backticks and escape internal backticks with backslash
        let escaped_content = key.replace('`', "\\`").replace('\\', "\\\\");
        format!("`{}`", escaped_content)
    } else {
        key.to_string()
    }
}

/// Unescape a SurrealDB record ID key back to the original user key
pub fn unescape_key(escaped_key: &str) -> Result<String, VaultError> {
    if escaped_key.starts_with('`') && escaped_key.ends_with('`') {
        // Remove backticks and unescape internal characters
        let content = &escaped_key[1..escaped_key.len() - 1];
        let unescaped = content.replace("\\`", "`").replace("\\\\", "\\");
        Ok(unescaped)
    } else {
        // Not escaped, return as-is
        Ok(escaped_key.to_string())
    }
}

/// Extract the key portion from a SurrealDB record ID in format "table:key"
pub fn extract_key_from_record_id(record_id: &str) -> Result<String, VaultError> {
    let parts: Vec<&str> = record_id.splitn(2, ':').collect();
    if parts.len() != 2 {
        return Err(VaultError::InvalidInput(format!(
            "Invalid record ID format, expected 'table:key', got: {}",
            record_id
        )));
    }

    // The key part is already escaped, so unescape it
    unescape_key(parts[1])
}

/// Create a record ID string in format "vault_entries:escaped_key"
pub fn create_record_id(key: &str) -> String {
    format!("vault_entries:{}", escape_key(key))
}

/// Validate that a key is suitable for use as a SurrealDB record ID
pub fn validate_key(key: &str) -> Result<(), VaultError> {
    if key.is_empty() {
        return Err(VaultError::InvalidKey("Key cannot be empty".to_string()));
    }

    if key.len() > 1024 {
        return Err(VaultError::InvalidKey(
            "Key too long (max 1024 characters)".to_string(),
        ));
    }

    // Additional validation - ensure key doesn't start with record ID delimiter
    if key.starts_with("vault_entries:") {
        return Err(VaultError::InvalidKey(
            "Key cannot start with 'vault_entries:' as it's reserved for internal use".to_string(),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_escape_simple_key() {
        assert_eq!(escape_key("simple_key"), "simple_key");
        assert_eq!(escape_key("key123"), "key123");
    }

    #[test]
    fn test_escape_special_characters() {
        assert_eq!(escape_key("key with spaces"), "`key with spaces`");
        assert_eq!(escape_key("key/with/slashes"), "`key/with/slashes`");
        assert_eq!(escape_key("key@domain.com"), "`key@domain.com`");
    }

    #[test]
    fn test_roundtrip_escaping() {
        let original = "test key with special chars: @#$%^&*()";
        let escaped = escape_key(original);
        let unescaped = unescape_key(&escaped).unwrap();
        assert_eq!(original, unescaped);
    }

    #[test]
    fn test_extract_key_from_record_id() {
        let record_id = "vault_entries:simple_key";
        let key = extract_key_from_record_id(record_id).unwrap();
        assert_eq!(key, "simple_key");
    }

    #[test]
    fn test_create_record_id() {
        assert_eq!(create_record_id("test_key"), "vault_entries:test_key");
        assert_eq!(
            create_record_id("key with spaces"),
            "vault_entries:`key with spaces`"
        );
    }

    #[test]
    fn test_validate_key() {
        assert!(validate_key("valid_key").is_ok());
        assert!(validate_key("").is_err()); // Empty key
        assert!(validate_key(&"x".repeat(1025)).is_err()); // Too long
    }
}
