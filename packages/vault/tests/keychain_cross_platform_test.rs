//! Cross-platform keychain integration tests
//!
//! Tests that keychain storage/retrieval works with platform-specific features
//! and verifies real keychain behavior vs mock behavior

use cryypt_pqcrypto::api::KyberSecurityLevel as SecurityLevel;
use cryypt_vault::tui::cli::commands::{
    detect_current_key_version, generate_pq_keypair, load_pq_key_from_keychain,
};

#[tokio::test]
async fn test_cross_platform_keychain_storage() {
    // Test that keychain storage/retrieval works with platform-specific features
    let namespace = "test_cross_platform";
    let version = 42; // Use non-standard version to verify no hardcoded limits

    // Generate and store a key
    generate_pq_keypair(namespace, version, SecurityLevel::Level3)
        .await
        .expect("Failed to generate keypair");

    // Verify the key can be retrieved
    let retrieved_key = load_pq_key_from_keychain(namespace, version)
        .await
        .expect("Failed to retrieve key from keychain");

    // Verify key is not empty (actual keychain storage, not mock)
    assert!(!retrieved_key.is_empty());
    assert!(retrieved_key.len() > 1000); // PQCrypto keys are large

    // Test version detection with non-standard version
    let detected_version = detect_current_key_version(namespace)
        .await
        .expect("Failed to detect version");
    assert_eq!(detected_version, version);

    // Test that non-existent version returns error
    let non_existent = load_pq_key_from_keychain(namespace, version + 1).await;
    assert!(non_existent.is_err());
}

#[tokio::test]
async fn test_keychain_persistence_across_sessions() {
    // Test that keys persist across different "sessions" (function calls)
    let namespace = "test_persistence";
    let version = 123;

    // Generate and store a key
    generate_pq_keypair(namespace, version, SecurityLevel::Level3)
        .await
        .expect("Failed to generate keypair");

    // Retrieve the key multiple times to verify persistence
    for _ in 0..3 {
        let retrieved_key = load_pq_key_from_keychain(namespace, version)
            .await
            .expect("Failed to retrieve key from keychain");

        assert!(!retrieved_key.is_empty());
        assert!(retrieved_key.len() > 1000);
    }

    // Verify version detection works consistently
    for _ in 0..3 {
        let detected_version = detect_current_key_version(namespace)
            .await
            .expect("Failed to detect version");
        assert_eq!(detected_version, version);
    }
}

#[tokio::test]
async fn test_keychain_namespace_isolation() {
    // Test that different namespaces are properly isolated
    let namespace1 = "test_isolation_ns1";
    let namespace2 = "test_isolation_ns2";
    let version = 1;

    // Generate keys in both namespaces
    generate_pq_keypair(namespace1, version, SecurityLevel::Level3)
        .await
        .expect("Failed to generate keypair for namespace1");

    generate_pq_keypair(namespace2, version, SecurityLevel::Level3)
        .await
        .expect("Failed to generate keypair for namespace2");

    // Verify both keys can be retrieved independently
    let key1 = load_pq_key_from_keychain(namespace1, version)
        .await
        .expect("Failed to retrieve key from namespace1");

    let key2 = load_pq_key_from_keychain(namespace2, version)
        .await
        .expect("Failed to retrieve key from namespace2");

    // Keys should be different (different namespaces generate different keys)
    assert_ne!(key1, key2);

    // Version detection should work independently for each namespace
    let version1 = detect_current_key_version(namespace1)
        .await
        .expect("Failed to detect version for namespace1");
    let version2 = detect_current_key_version(namespace2)
        .await
        .expect("Failed to detect version for namespace2");

    assert_eq!(version1, 1);
    assert_eq!(version2, 1);
}

#[tokio::test]
async fn test_keychain_large_version_numbers() {
    // Test that the system handles large version numbers without arbitrary limits
    let namespace = "test_large_versions";
    let large_version = 999999;

    // Generate key with large version number
    generate_pq_keypair(namespace, large_version, SecurityLevel::Level3)
        .await
        .expect("Failed to generate keypair with large version");

    // Verify retrieval works
    let retrieved_key = load_pq_key_from_keychain(namespace, large_version)
        .await
        .expect("Failed to retrieve key with large version");

    assert!(!retrieved_key.is_empty());
    assert!(retrieved_key.len() > 1000);

    // Verify version detection finds the large version
    let detected_version = detect_current_key_version(namespace)
        .await
        .expect("Failed to detect large version");
    assert_eq!(detected_version, large_version);
}

#[tokio::test]
async fn test_keychain_error_handling() {
    // Test proper error handling for non-existent keys
    let namespace = "test_nonexistent";
    let version = 999;

    // Try to retrieve non-existent key
    let result = load_pq_key_from_keychain(namespace, version).await;
    assert!(result.is_err());

    // Error message should be meaningful
    let error_msg = result.unwrap_err();
    assert!(error_msg.contains("not found") || error_msg.contains("keychain"));

    // Version detection should fail for namespace with no keys
    let version_result = detect_current_key_version(namespace).await;
    assert!(version_result.is_err());

    let version_error = version_result.unwrap_err();
    assert!(version_error.contains("No keys found"));
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

    for (i, level) in security_levels.iter().enumerate() {
        let version = (i + 1) as u32;

        // Generate key with specific security level
        generate_pq_keypair(namespace, version, *level)
            .await
            .expect("Failed to generate keypair");

        // Verify retrieval works
        let retrieved_key = load_pq_key_from_keychain(namespace, version)
            .await
            .expect("Failed to retrieve key");

        assert!(!retrieved_key.is_empty());
        // Different security levels may have different key sizes
        assert!(retrieved_key.len() > 500);
    }

    // Verify version detection finds the highest version
    let detected_version = detect_current_key_version(namespace)
        .await
        .expect("Failed to detect version");
    assert_eq!(detected_version, security_levels.len() as u32);
}
