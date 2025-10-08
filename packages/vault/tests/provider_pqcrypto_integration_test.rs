//! Integration tests for PQCrypto provider operations
//!
//! Tests validate end-to-end PQCrypto functionality including:
//! - Provider armor/unarmor cycle with keychain
//! - Key rotation with vault re-encryption
//! - Data integrity across encryption operations
//! - Error handling for invalid operations

use cryypt_pqcrypto::api::KyberSecurityLevel as SecurityLevel;
use cryypt_vault::config::{KeychainConfig, VaultConfig};
use cryypt_vault::core::VaultValue;
use cryypt_vault::db::vault_store::LocalVaultProvider;
use cryypt_vault::error::VaultError;
use cryypt_vault::operation::{Passphrase, VaultOperation};
use cryypt_vault::tui::cli::commands::{
    detect_current_key_version, generate_pq_keypair, rotate_pq_keys,
};
use std::path::{Path, PathBuf};
use tempfile::{TempDir, tempdir};
use tokio::fs;
use tokio::task::LocalSet;

/// Create SurrealKV-compatible vault database with test data
async fn create_test_vault_db(
    vault_path: &Path,
    content: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = VaultConfig {
        vault_path: vault_path.to_path_buf(),
        keychain_config: KeychainConfig {
            app_name: "vault".to_string(),
            pq_namespace: "test_pqcrypto".to_string(),
            auto_generate: true,
        },
        ..Default::default()
    };

    let provider = LocalVaultProvider::new(config).await?;

    // Unlock vault and add test data
    let passphrase = Passphrase::from("test_passphrase".to_string());
    let unlock_request = provider.unlock(&passphrase);
    unlock_request.await?;

    // Add test content
    provider
        .put(
            "test_content",
            &VaultValue::from_string(content.to_string()),
        )
        .await?;

    Ok(())
}

/// Create test provider with temporary vault and keychain config
async fn create_test_provider() -> (LocalVaultProvider, TempDir, PathBuf) {
    let temp_dir = tempdir().expect("Failed to create temp directory");
    let vault_path = temp_dir.path().join("test_vault.db");

    // DON'T create dummy file - let SurrealKV manage the database
    // fs::write(&vault_path, b"test vault database content").await  // REMOVED THIS LINE

    let config = VaultConfig {
        vault_path: vault_path.clone(),
        keychain_config: KeychainConfig {
            app_name: "vault".to_string(),
            pq_namespace: "test_pqcrypto".to_string(),
            auto_generate: true,
        },
        ..Default::default()
    };

    let provider = LocalVaultProvider::new(config)
        .await
        .expect("Failed to create test provider");

    // CRITICAL: Unlock vault before adding data
    let passphrase = Passphrase::from("test_passphrase".to_string());
    let unlock_request = provider.unlock(&passphrase);
    unlock_request.await.expect("Failed to unlock vault");

    // Now vault is unlocked and can accept data
    provider
        .put(
            "test_key",
            &VaultValue::from_string("test data".to_string()),
        )
        .await
        .expect("Failed to add test data");

    (provider, temp_dir, vault_path)
}

#[tokio::test]
async fn test_provider_pqcrypto_armor_cycle() {
    // Create provider directly within LocalSet context to avoid spawn_local issues
    let temp_dir = tempdir().expect("Failed to create temp directory");
    let vault_path = temp_dir.path().join("test_vault.db");

    let config = VaultConfig {
        vault_path: vault_path.clone(),
        keychain_config: KeychainConfig {
            app_name: "vault".to_string(),
            pq_namespace: "test_pqcrypto".to_string(),
            auto_generate: true,
        },
        ..Default::default()
    };

    let provider = LocalVaultProvider::new(config)
        .await
        .expect("Failed to create test provider");

    // CRITICAL: Unlock vault before adding data (this uses spawn_local internally)
    let passphrase = Passphrase::from("test_passphrase".to_string());
    let unlock_request = provider.unlock(&passphrase);
    unlock_request.await.expect("Failed to unlock vault");

    // Now vault is unlocked and can accept data
    provider
        .put(
            "test_key",
            &VaultValue::from_string("test data".to_string()),
        )
        .await
        .expect("Failed to add test data");

    // Verify test data exists via vault API
    let original_value = provider
        .get("test_key")
        .await
        .expect("Failed to get test data")
        .expect("Test key should exist");

    // Apply armor
    provider
        .apply_pqcrypto_armor()
        .await
        .expect("Failed to apply PQCrypto armor");

    // Verify file state changes
    let vault_file = vault_path.with_extension("vault");
    assert!(vault_file.exists(), ".vault file should exist after armor");
    assert!(
        !vault_path.exists(),
        ".db file should be removed after armor"
    );

    // Remove armor
    provider
        .remove_pqcrypto_armor()
        .await
        .expect("Failed to remove PQCrypto armor");

    // Verify .db file restored and .vault removed
    assert!(
        vault_path.exists(),
        ".db file should be restored after unarmor"
    );
    assert!(
        !vault_file.exists(),
        ".vault file should be removed after unarmor"
    );

    // Verify data integrity via vault API
    let recovered_value = provider
        .get("test_key")
        .await
        .expect("Failed to get recovered data")
        .expect("Recovered key should exist");

    assert_eq!(
        recovered_value.expose_as_str().expect("Invalid UTF-8"),
        original_value.expose_as_str().expect("Invalid UTF-8"),
        "Recovered data should match original"
    );

    println!("✅ Provider PQCrypto armor cycle test passed");
}

#[tokio::test(flavor = "current_thread")]
async fn test_key_rotation_with_re_encryption() {
    LocalSet::new()
        .run_until(async {
            let temp_dir = tempdir().expect("Failed to create temp directory");
            let namespace = "test_rotation";

            // Create multiple test vaults
            let vault_paths: Vec<PathBuf> = (1..=3)
                .map(|i| temp_dir.path().join(format!("test_vault_{}.db", i)))
                .collect();

            // Create test vault databases using SurrealKV-compatible approach
            for (i, path) in vault_paths.iter().enumerate() {
                let content = format!("test vault {} content", i + 1);
                create_test_vault_db(path, &content)
                    .await
                    .expect("Failed to create test vault database");
            }

            // Step 1: Generate initial PQCrypto keys (version 1)
            generate_pq_keypair(namespace, 1, SecurityLevel::Level3)
                .await
                .expect("Failed to generate initial PQ keypair");

            // Step 2: Encrypt all vaults with version 1 keys
            for vault_path in &vault_paths {
                cryypt_vault::tui::cli::commands::handle_lock_command(
                    vault_path, None, // Use keychain
                    namespace, 1, false,
                )
                .await
                .expect("Failed to lock vault with version 1 keys");
            }

            // Verify all vaults are locked (.vault files exist)
            for vault_path in &vault_paths {
                let vault_file = vault_path.with_extension("vault");
                assert!(
                    vault_file.exists(),
                    "Vault should be locked with version 1 keys"
                );
                assert!(
                    !vault_path.exists(),
                    "Original .db should be removed after locking"
                );
            }

            // Step 3: Rotate keys (should re-encrypt with version 2)
            let new_version = rotate_pq_keys(namespace, 1, vault_paths.clone())
                .await
                .expect("Failed to rotate PQ keys");
            assert_eq!(new_version, 2, "New version should be 2");

            // Step 4: Verify vaults can be unlocked with new keys (version 2)
            for vault_path in &vault_paths {
                cryypt_vault::tui::cli::commands::handle_unlock_command(
                    vault_path, None, // Use keychain
                    namespace, 2, // New version
                    false,
                )
                .await
                .expect("Failed to unlock vault with version 2 keys");
            }

            // Step 5: Verify data integrity after rotation using vault API
            for (i, vault_path) in vault_paths.iter().enumerate() {
                assert!(
                    vault_path.exists(),
                    "Vault should be unlocked after rotation"
                );

                // Create provider to verify data via vault API
                let config = VaultConfig {
                    vault_path: vault_path.clone(),
                    keychain_config: KeychainConfig {
                        app_name: "vault".to_string(),
                        pq_namespace: "test_pqcrypto".to_string(),
                        auto_generate: true,
                    },
                    ..Default::default()
                };

                let provider = LocalVaultProvider::new(config)
                    .await
                    .expect("Failed to create provider for verification");

                // Unlock and verify content
                let passphrase = Passphrase::from("test_passphrase".to_string());
                let unlock_request = provider.unlock(&passphrase);
                unlock_request
                    .await
                    .expect("Failed to unlock vault for verification");

                let recovered_value = provider
                    .get("test_content")
                    .await
                    .expect("Failed to get test content")
                    .expect("Test content should exist");

                let expected_content = format!("test vault {} content", i + 1);
                assert_eq!(
                    recovered_value.expose_as_str().expect("Invalid UTF-8"),
                    expected_content,
                    "Content should be preserved after key rotation"
                );
            }

            // Step 6: Verify version detection works
            let detected_version = detect_current_key_version(namespace)
                .await
                .expect("Failed to detect current key version");
            assert_eq!(detected_version, 2, "Should detect version 2 as current");

            println!("✅ Key rotation with re-encryption test passed");
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn test_armor_format_error_handling() {
    LocalSet::new()
        .run_until(async {
            let (provider, _temp_dir, vault_path) = create_test_provider().await;

            // Test with corrupted .vault file
            let vault_file = vault_path.with_extension("vault");
            fs::write(&vault_file, b"corrupted data")
                .await
                .expect("Failed to write corrupted vault file");

            // Remove original .db file to simulate locked state
            fs::remove_file(&vault_path).await.ok();

            // Attempt to remove armor should fail gracefully
            let result = provider.remove_pqcrypto_armor().await;
            assert!(result.is_err(), "Should fail with corrupted armor data");

            match result {
                Err(VaultError::Provider(msg)) => {
                    assert!(
                        msg.contains("Failed to parse armor format"),
                        "Should have specific error message: {}",
                        msg
                    );
                }
                _ => panic!("Should return Provider error for corrupted armor"),
            }

            println!("✅ Armor format error handling test passed");
        })
        .await;
}
