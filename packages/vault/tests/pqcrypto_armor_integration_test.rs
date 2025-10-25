//! Comprehensive PQCrypto armor integration tests
//!
//! Tests the complete workflow: generate keys → lock → unlock with UUID-based keys

use cryypt_pqcrypto::api::KyberSecurityLevel as SecurityLevel;
use cryypt_vault::tui::cli::commands::{
    generate_pq_keypair, generate_unique_key_id, handle_lock_command, handle_unlock_command,
};
use std::path::PathBuf;

#[tokio::test]
async fn test_complete_pqcrypto_workflow_with_uuid_keys() {
    // Test the complete workflow: generate UUID keys → lock → unlock
    // Use relative path within current directory to avoid security validation issues
    let vault_path = std::path::PathBuf::from("test_uuid_workflow.db");
    let key_id = generate_unique_key_id("test_auto_namespace");

    // Clean up any existing test file
    let _ = tokio::fs::remove_file(&vault_path).await;
    let _ = tokio::fs::remove_file(vault_path.with_extension("vault")).await;

    // Create test vault database
    tokio::fs::write(&vault_path, b"test vault content for UUID keys")
        .await
        .expect("Failed to write test vault");

    // Generate UUID-based keys
    generate_pq_keypair(&key_id, SecurityLevel::Level3)
        .await
        .expect("Failed to generate keypair");

    // Test lock with UUID key_id
    handle_lock_command(&vault_path, None, &key_id, false)
        .await
        .expect("Failed to lock vault");

    // Verify .vault file exists and .db is removed
    assert!(!vault_path.exists());
    assert!(vault_path.with_extension("vault").exists());

    // Test unlock with UUID key_id
    handle_unlock_command(&vault_path, None, &key_id, false)
        .await
        .expect("Failed to unlock vault");

    // Verify .db file restored and .vault is removed
    assert!(vault_path.exists());
    assert!(!vault_path.with_extension("vault").exists());

    // Verify content integrity
    let recovered_content = tokio::fs::read(&vault_path)
        .await
        .expect("Failed to read recovered content");
    assert_eq!(recovered_content, b"test vault content for UUID keys");

    // Clean up test file
    let _ = tokio::fs::remove_file(&vault_path).await;
}

#[tokio::test]
async fn test_lock_unlock_cycle_preserves_data() {
    // Test that lock/unlock cycle preserves data integrity with UUID keys
    // Use relative path within current directory to avoid security validation issues
    let vault_path = std::path::PathBuf::from("test_integrity_cycle.db");
    let key_id = generate_unique_key_id("test_integrity_namespace");

    // Clean up any existing test file
    let _ = tokio::fs::remove_file(&vault_path).await;
    let _ = tokio::fs::remove_file(vault_path.with_extension("vault")).await;

    // Create test data with various content types
    let test_data = b"Complex test data with\nnewlines\x00null bytes\xFF and binary content";
    tokio::fs::write(&vault_path, test_data)
        .await
        .expect("Failed to write test data");

    // Generate keys
    generate_pq_keypair(&key_id, SecurityLevel::Level3)
        .await
        .expect("Failed to generate keypair");

    // Lock the vault
    handle_lock_command(&vault_path, None, &key_id, false)
        .await
        .expect("Failed to lock vault");

    // Verify locked state
    assert!(!vault_path.exists());
    let vault_file = vault_path.with_extension("vault");
    assert!(vault_file.exists());

    // Unlock the vault
    handle_unlock_command(&vault_path, None, &key_id, false)
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
