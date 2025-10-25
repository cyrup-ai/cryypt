//! Cross-platform keychain integration tests
//!
//! Tests that keychain storage/retrieval works with platform-specific features
//! and verifies real keychain behavior vs mock behavior

use cryypt_pqcrypto::api::KyberSecurityLevel as SecurityLevel;
use cryypt_vault::tui::cli::commands::{
    generate_pq_keypair, generate_unique_key_id, load_pq_key_from_keychain,
};

#[tokio::test]
async fn test_cross_platform_keychain_storage() {
    // Test that keychain storage/retrieval works with platform-specific features
    let key_id = generate_unique_key_id("test_cross_platform");

    // Generate and store a key
    generate_pq_keypair(&key_id, SecurityLevel::Level3)
        .await
        .expect("Failed to generate keypair");

    // Verify the key can be retrieved
    let retrieved_key = load_pq_key_from_keychain(&key_id)
        .await
        .expect("Failed to retrieve key from keychain");

    // Verify key is not empty (actual keychain storage, not mock)
    assert!(!retrieved_key.is_empty());
    assert!(retrieved_key.len() > 1000); // PQCrypto keys are large

    // Test that non-existent key_id returns error
    let non_existent_key_id = generate_unique_key_id("test_nonexistent");
    let non_existent = load_pq_key_from_keychain(&non_existent_key_id).await;
    assert!(non_existent.is_err());
}

#[tokio::test]
async fn test_keychain_persistence_across_sessions() {
    // Test that keys persist across different "sessions" (function calls)
    let key_id = generate_unique_key_id("test_persistence");

    // Generate and store a key
    generate_pq_keypair(&key_id, SecurityLevel::Level3)
        .await
        .expect("Failed to generate keypair");

    // Retrieve the key multiple times to verify persistence
    for _ in 0..3 {
        let retrieved_key = load_pq_key_from_keychain(&key_id)
            .await
            .expect("Failed to retrieve key from keychain");

        assert!(!retrieved_key.is_empty());
        assert!(retrieved_key.len() > 1000);
    }
}

#[tokio::test]
async fn test_keychain_namespace_isolation() {
    // Test that different namespaces are properly isolated
    let key_id1 = generate_unique_key_id("test_isolation_ns1");
    let key_id2 = generate_unique_key_id("test_isolation_ns2");

    // Generate keys in both namespaces
    generate_pq_keypair(&key_id1, SecurityLevel::Level3)
        .await
        .expect("Failed to generate keypair for namespace1");

    generate_pq_keypair(&key_id2, SecurityLevel::Level3)
        .await
        .expect("Failed to generate keypair for namespace2");

    // Verify both keys can be retrieved independently
    let key1 = load_pq_key_from_keychain(&key_id1)
        .await
        .expect("Failed to retrieve key from namespace1");

    let key2 = load_pq_key_from_keychain(&key_id2)
        .await
        .expect("Failed to retrieve key from namespace2");

    // Keys should be different (different UUIDs generate different keys)
    assert_ne!(key1, key2);
}

#[tokio::test]
async fn test_keychain_error_handling() {
    // Test proper error handling for non-existent keys
    let non_existent_key_id = generate_unique_key_id("test_nonexistent_error");

    // Try to retrieve non-existent key
    let result = load_pq_key_from_keychain(&non_existent_key_id).await;
    assert!(result.is_err());

    // Error message should be meaningful
    let error_msg = result.unwrap_err();
    assert!(
        error_msg.contains("not found") || error_msg.contains("Item not found"),
        "Error should indicate key not found: {}",
        error_msg
    );
}

#[tokio::test]
async fn test_keychain_security_levels() {
    // Test that different security levels work with keychain storage
    let namespace = "test_security_levels";

    // Test all security levels
    let security_levels = [
        SecurityLevel::Level1,
        SecurityLevel::Level3,
        SecurityLevel::Level5,
    ];

    for level in security_levels.iter() {
        let key_id = generate_unique_key_id(namespace);

        // Generate key with specific security level
        generate_pq_keypair(&key_id, *level)
            .await
            .expect("Failed to generate keypair");

        // Verify retrieval works
        let retrieved_key = load_pq_key_from_keychain(&key_id)
            .await
            .expect("Failed to retrieve key");

        assert!(!retrieved_key.is_empty());
        // Different security levels may have different key sizes
        assert!(retrieved_key.len() > 500);
    }
}
