//! Comprehensive PQCrypto armor integration tests
//!
//! Tests the complete workflow: generate keys → lock → unlock with auto-version detection

use cryypt_pqcrypto::api::KyberSecurityLevel as SecurityLevel;
use cryypt_vault::tui::cli::commands::{
    detect_current_key_version, generate_pq_keypair, handle_lock_command, handle_unlock_command,
};
use std::path::PathBuf;
use tempfile::tempdir;

#[tokio::test]
async fn test_complete_pqcrypto_workflow_with_auto_version() {
    // Test the complete workflow: generate keys → lock → unlock with auto-version detection
    // Use relative path within current directory to avoid security validation issues
    let vault_path = std::path::PathBuf::from("test_auto_workflow.db");
    let namespace = "test_auto_namespace";

    // Clean up any existing test file
    let _ = tokio::fs::remove_file(&vault_path).await;

    // Create test vault database
    tokio::fs::write(&vault_path, b"test vault content for auto version")
        .await
        .expect("Failed to write test vault");

    // Generate initial keys (should create version 1)
    generate_pq_keypair(namespace, 1, SecurityLevel::Level3)
        .await
        .expect("Failed to generate keypair");

    // Verify version detection finds version 1
    let detected_version = detect_current_key_version(namespace)
        .await
        .expect("Failed to detect version");
    assert_eq!(detected_version, 1);

    // Test lock with auto-detected version
    handle_lock_command(&vault_path, None, namespace, detected_version, false)
        .await
        .expect("Failed to lock vault");

    // Verify .vault file exists and .db is removed
    assert!(!vault_path.exists());
    assert!(vault_path.with_extension("vault").exists());

    // Test unlock with auto-detected version
    handle_unlock_command(&vault_path, None, namespace, detected_version, false)
        .await
        .expect("Failed to unlock vault");

    // Verify .db file restored and .vault is removed
    assert!(vault_path.exists());
    assert!(!vault_path.with_extension("vault").exists());

    // Verify content integrity
    let recovered_content = tokio::fs::read(&vault_path)
        .await
        .expect("Failed to read recovered content");
    assert_eq!(recovered_content, b"test vault content for auto version");

    // Clean up test file
    let _ = tokio::fs::remove_file(&vault_path).await;
}

#[tokio::test]
async fn test_version_detection_with_multiple_keys() {
    // Test version detection with multiple key versions
    let namespace = "test_multi_version";

    // Generate multiple key versions
    for version in 1..=5 {
        generate_pq_keypair(namespace, version, SecurityLevel::Level3)
            .await
            .expect("Failed to generate keypair");
    }

    // Verify version detection finds the highest version (5)
    let detected_version = detect_current_key_version(namespace)
        .await
        .expect("Failed to detect version");
    assert_eq!(detected_version, 5);
}

#[tokio::test]
async fn test_version_detection_no_keys() {
    // Test version detection when no keys exist
    let namespace = "test_no_keys_namespace";

    // Verify version detection returns error when no keys exist
    let result = detect_current_key_version(namespace).await;
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .contains("No keys found in keychain for namespace")
    );
}

#[tokio::test]
async fn test_lock_unlock_cycle_preserves_data() {
    // Test that lock/unlock cycle preserves data integrity
    // Use relative path within current directory to avoid security validation issues
    let vault_path = std::path::PathBuf::from("test_integrity_cycle.db");
    let namespace = "test_integrity_namespace";

    // Clean up any existing test file
    let _ = tokio::fs::remove_file(&vault_path).await;

    // Create test data with various content types
    let test_data = b"Complex test data with\nnewlines\x00null bytes\xFF and binary content";
    tokio::fs::write(&vault_path, test_data)
        .await
        .expect("Failed to write test data");

    // Generate keys
    generate_pq_keypair(namespace, 1, SecurityLevel::Level3)
        .await
        .expect("Failed to generate keypair");

    // Get version
    let version = detect_current_key_version(namespace)
        .await
        .expect("Failed to detect version");

    // Lock the vault
    handle_lock_command(&vault_path, None, namespace, version, false)
        .await
        .expect("Failed to lock vault");

    // Verify locked state
    assert!(!vault_path.exists());
    let vault_file = vault_path.with_extension("vault");
    assert!(vault_file.exists());

    // Unlock the vault
    handle_unlock_command(&vault_path, None, namespace, version, false)
        .await
        .expect("Failed to unlock vault");

    // Verify unlocked state and data integrity
    assert!(vault_path.exists());
    assert!(!vault_file.exists());

    let recovered_data = tokio::fs::read(&vault_path)
        .await
        .expect("Failed to read recovered data");
    assert_eq!(recovered_data, test_data);

    // Clean up test file
    let _ = tokio::fs::remove_file(&vault_path).await;
}
