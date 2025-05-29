//! Integration tests for the cyrup-crypt library

use cyrup_crypt::{
    CryptError, EncryptedData, Crypt,
    cipher::{CipherAlgorithm, AesGcmCipher, ChaChaPolyCipher},
    cascade::CascadeCipher,
    factory::CipherFactory,
    traits::{Cipher, Encryptor, Decryptor},
    key::{StandardKeyId, KeyManager},
    provider::{CryptProvider, VersionRequirement},
};
use std::sync::Arc;

#[tokio::test]
async fn test_factory_creates_all_ciphers() {
    let factory = CipherFactory::new();
    
    // Test AES-256-GCM creation
    #[cfg(feature = "aes")]
    {
        let aes_cipher = factory.create_cipher(CipherAlgorithm::Aes256Gcm).expect("Failed to create AES-256-GCM cipher");
        assert_eq!(aes_cipher.algorithm(), CipherAlgorithm::Aes256Gcm);
    }
    
    // Test ChaCha20-Poly1305 creation
    #[cfg(feature = "chacha")]
    {
        let chacha_cipher = factory.create_cipher(CipherAlgorithm::ChaCha20Poly1305).expect("Failed to create ChaCha20-Poly1305 cipher");
        assert_eq!(chacha_cipher.algorithm(), CipherAlgorithm::ChaCha20Poly1305);
    }
    
    // Test Cascade creation
    #[cfg(all(feature = "aes", feature = "chacha"))]
    {
        let cascade_cipher = factory.create_cipher(CipherAlgorithm::Cascade).expect("Failed to create Cascade cipher");
        assert_eq!(cascade_cipher.algorithm(), CipherAlgorithm::Cascade);
    }
}

#[tokio::test]
async fn test_factory_default_cipher() {
    let factory = CipherFactory::new();
    let default_cipher = factory.create_default_cipher().expect("Failed to create default cipher");
    
    // Should create the most secure available cipher
    let algorithm = default_cipher.algorithm();
    
    #[cfg(all(feature = "aes", feature = "chacha"))]
    assert_eq!(algorithm, CipherAlgorithm::Cascade);
    
    #[cfg(all(feature = "aes", not(feature = "chacha")))]
    assert_eq!(algorithm, CipherAlgorithm::Aes256Gcm);
    
    #[cfg(all(not(feature = "aes"), feature = "chacha"))]
    assert_eq!(algorithm, CipherAlgorithm::ChaCha20Poly1305);
}

#[tokio::test]
async fn test_sugar_api_encryption() {
    let plaintext = b"Test data for sugar API".to_vec();
    
    // Test simple encryption/decryption
    let encrypted = Crypt::encrypt(plaintext.clone()).await.expect("Failed to encrypt with sugar API");
    let decrypted = Crypt::decrypt(encrypted).await.expect("Failed to decrypt with sugar API");
    
    assert_eq!(plaintext, decrypted);
}

#[tokio::test]
async fn test_sugar_api_with_key() {
    let plaintext = b"Test data with custom key".to_vec();
    let key = "my-custom-key";
    
    // Encrypt with custom key
    let encrypted = Crypt::encrypt_with_key(plaintext.clone(), key).await.expect("Failed to encrypt with custom key");
    
    // Decrypt with same key
    let decrypted = Crypt::decrypt_with_key(encrypted.clone(), key).await.expect("Failed to decrypt with custom key");
    assert_eq!(plaintext, decrypted);
    
    // Try to decrypt with different key - should fail
    let wrong_key_result = Crypt::decrypt_with_key(encrypted, "wrong-key").await;
    assert!(wrong_key_result.is_err());
}

#[tokio::test]
async fn test_cross_cipher_incompatibility() {
    let key_id = Arc::new(StandardKeyId::new("test-key", 1));
    let plaintext = b"Test cross-cipher data".to_vec();
    
    // Encrypt with AES
    #[cfg(feature = "aes")]
    {
        let aes_cipher = AesGcmCipher::new();
        let encrypted = aes_cipher.encrypt(plaintext.clone(), Some(key_id.clone())).await.expect("Failed to encrypt with AES cipher");
        
        // Try to decrypt with ChaCha - should fail
        #[cfg(feature = "chacha")]
        {
            let chacha_cipher = ChaChaPolyCipher::new();
            let result = chacha_cipher.decrypt(encrypted, Some(key_id.clone())).await;
            assert!(matches!(result, Err(CryptError::UnsupportedAlgorithm(_))));
        }
    }
}

#[tokio::test]
async fn test_provider_basic_operations() {
    let provider = CryptProvider::new();
    let namespace = "test-namespace";
    let key = "test-key";
    let plaintext = b"Provider test data".to_vec();
    
    // Set encrypted value
    provider.set(namespace, key, plaintext.clone()).await.expect("Failed to set value in provider");
    
    // Get encrypted value
    let retrieved = provider.get(namespace, key).await.expect("Failed to get value from provider");
    assert_eq!(plaintext, retrieved);
    
    // Delete value
    provider.delete(namespace, key).await.expect("Failed to delete value from provider");
    
    // Try to get deleted value - should fail
    let result = provider.get(namespace, key).await;
    assert!(matches!(result, Err(CryptError::NotFound(_))));
}

#[tokio::test]
async fn test_provider_list_operations() {
    let provider = CryptProvider::new();
    let namespace = "list-test";
    
    // Set multiple values
    for i in 0..5 {
        let key = format!("key-{}", i);
        let value = format!("value-{}", i).into_bytes();
        provider.set(namespace, &key, value).await.expect("Failed to set value in list test");
    }
    
    // List all keys
    let keys = provider.list(namespace, None).await.expect("Failed to list all keys");
    assert_eq!(keys.len(), 5);
    
    // List with prefix
    provider.set(namespace, "prefix-1", b"data1".to_vec()).await.expect("Failed to set prefix-1");
    provider.set(namespace, "prefix-2", b"data2".to_vec()).await.expect("Failed to set prefix-2");
    
    let prefix_keys = provider.list(namespace, Some("prefix-")).await.expect("Failed to list keys with prefix");
    assert_eq!(prefix_keys.len(), 2);
}

#[tokio::test]
async fn test_key_rotation() {
    let provider = CryptProvider::new();
    let namespace = "rotation-test";
    let key = "rotating-key";
    
    // Set value with version 1
    let value_v1 = b"Version 1 data".to_vec();
    provider.set(namespace, key, value_v1.clone()).await.expect("Failed to set value before rotation");
    
    // Rotate key (this would normally involve changing the encryption key)
    provider.rotate_key(namespace, key).await.expect("Failed to rotate key");
    
    // Get value - should still work after rotation
    let retrieved = provider.get(namespace, key).await.expect("Failed to get value after rotation");
    assert_eq!(value_v1, retrieved);
}

#[tokio::test]
async fn test_batch_operations() {
    let provider = CryptProvider::new();
    let namespace = "batch-test";
    
    // Prepare batch data
    let mut batch_data = Vec::new();
    for i in 0..10 {
        let key = format!("batch-key-{}", i);
        let value = format!("batch-value-{}", i).into_bytes();
        batch_data.push((key, value));
    }
    
    // Set batch
    let keys: Vec<String> = batch_data.iter().map(|(k, _)| k.clone()).collect();
    let values: Vec<Vec<u8>> = batch_data.iter().map(|(_, v)| v.clone()).collect();
    
    for (key, value) in keys.iter().zip(values.iter()) {
        provider.set(namespace, key, value.clone()).await.expect("Failed to set value in batch");
    }
    
    // Get batch
    for (key, expected_value) in keys.iter().zip(values.iter()) {
        let retrieved = provider.get(namespace, key).await.expect("Failed to get value in batch verification");
        assert_eq!(*expected_value, retrieved);
    }
}

#[tokio::test]
async fn test_provider_with_custom_cipher() {
    let factory = CipherFactory::new();
    
    #[cfg(feature = "chacha")]
    {
        let chacha_cipher = factory.create_cipher(CipherAlgorithm::ChaCha20Poly1305).expect("Failed to create ChaCha cipher for provider");
        let provider = CryptProvider::with_cipher(chacha_cipher);
        
        let namespace = "custom-cipher";
        let key = "test-key";
        let value = b"ChaCha encrypted data".to_vec();
        
        // Set and get with custom cipher
        provider.set(namespace, key, value.clone()).await.expect("Failed to set value with custom cipher");
        let retrieved = provider.get(namespace, key).await.expect("Failed to get value with custom cipher");
        assert_eq!(value, retrieved);
    }
}

#[tokio::test]
async fn test_concurrent_provider_access() {
    use tokio::task::JoinSet;
    
    let provider = Arc::new(CryptProvider::new());
    let namespace = "concurrent-test";
    
    let mut tasks = JoinSet::new();
    
    // Spawn concurrent write tasks
    for i in 0..20 {
        let provider_clone = Arc::clone(&provider);
        let key = format!("concurrent-{}", i);
        let value = format!("value-{}", i).into_bytes();
        
        tasks.spawn(async move {
            provider_clone.set(namespace, &key, value.clone()).await.expect("Failed to set value in concurrent task");
            // Immediately read back
            let retrieved = provider_clone.get(namespace, &key).await.expect("Failed to get value in concurrent task");
            assert_eq!(value, retrieved);
            i
        });
    }
    
    // Wait for all tasks
    let mut completed = 0;
    while let Some(result) = tasks.join_next().await {
        result.expect("Concurrent task failed");
        completed += 1;
    }
    
    assert_eq!(completed, 20);
}

#[tokio::test]
async fn test_version_requirements() {
    let provider = CryptProvider::new();
    let namespace = "version-test";
    let key = "versioned-key";
    
    // Set initial version
    let v1_data = b"Version 1".to_vec();
    provider.set(namespace, key, v1_data.clone()).await.expect("Failed to set initial version");
    
    // Get with any version requirement
    let result = provider.get_with_version(
        namespace, 
        key, 
        VersionRequirement::Any
    ).await.expect("Failed to get with Any version requirement");
    assert_eq!(v1_data, result);
    
    // Get with exact version requirement
    let result = provider.get_with_version(
        namespace, 
        key, 
        VersionRequirement::Exact(1)
    ).await.expect("Failed to get with Exact version requirement");
    assert_eq!(v1_data, result);
    
    // Get with wrong exact version - should fail
    let result = provider.get_with_version(
        namespace, 
        key, 
        VersionRequirement::Exact(2)
    ).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_encryption_metadata() {
    let cipher = AesGcmCipher::new();
    let key_id = Arc::new(StandardKeyId::new("metadata-test", 1));
    let plaintext = b"Test with metadata".to_vec();
    
    // Encrypt
    let encrypted = cipher.encrypt(plaintext.clone(), Some(key_id.clone())).await.expect("Failed to encrypt with metadata test");
    
    // Verify metadata
    assert_eq!(encrypted.key_id(), "metadata-test:1");
    assert_eq!(encrypted.algorithm(), CipherAlgorithm::Aes256Gcm);
    assert_eq!(encrypted.nonce().len(), 12);
    
    // Validate structure
    encrypted.validate().expect("Failed to validate encrypted data structure");
}

#[tokio::test]
async fn test_cascade_fallback() {
    #[cfg(all(feature = "aes", feature = "chacha"))]
    {
        let cascade = CascadeCipher::new();
        let key_id = Arc::new(StandardKeyId::new("cascade-test", 1));
        
        // Test that cascade properly uses both ciphers
        let plaintext = b"Cascade test data".to_vec();
        let encrypted = cascade.encrypt(plaintext.clone(), Some(key_id.clone())).await.expect("Failed to encrypt with cascade cipher");
        
        // The encrypted data should be larger due to dual encryption
        // (though this is implementation detail)
        assert!(encrypted.ciphertext().len() > plaintext.len());
        
        // Should decrypt properly
        let decrypted = cascade.decrypt(encrypted, Some(key_id)).await.expect("Failed to decrypt cascade encrypted data");
        assert_eq!(plaintext, decrypted);
    }
}

#[tokio::test]
async fn test_error_propagation() {
    let factory = CipherFactory::new();
    
    // Test unavailable algorithm
    #[cfg(not(feature = "aes"))]
    {
        let result = factory.create_cipher(CipherAlgorithm::Aes256Gcm);
        assert!(matches!(result, Err(CryptError::UnsupportedAlgorithm(_))));
    }
    
    // Test invalid key ID parsing
    use std::str::FromStr;
    let result = StandardKeyId::from_str("invalid::key::format");
    assert!(result.is_err());
}

#[tokio::test]
#[cfg(feature = "rotation-duration")]
async fn test_time_based_features() {
    use cyrup_crypt::time_based::TimeBasedKey;
    
    let key = TimeBasedKey::new("time-key", std::time::Duration::from_secs(60));
    
    // Key should be valid initially
    assert!(key.is_valid());
    
    // Test expiration (would need to mock time in real tests)
    let expired_at = key.expires_at();
    assert!(expired_at > chrono::Utc::now());
}

#[tokio::test]
async fn test_builder_pattern() {
    let builder = Crypt::builder()
        .algorithm(CipherAlgorithm::Aes256Gcm)
        .key("custom-key")
        .namespace("custom-namespace");
    
    let plaintext = b"Builder pattern test".to_vec();
    let encrypted = builder.encrypt(plaintext.clone()).await.expect("Failed to encrypt with builder pattern");
    let decrypted = builder.decrypt(encrypted).await.expect("Failed to decrypt with builder pattern");
    
    assert_eq!(plaintext, decrypted);
}

#[tokio::test]
async fn test_streaming_operations() {
    use futures::StreamExt;
    
    let provider = CryptProvider::new();
    let namespace = "stream-test";
    
    // Set up test data
    for i in 0..100 {
        let key = format!("stream-key-{:03}", i);
        let value = format!("stream-value-{}", i).into_bytes();
        provider.set(namespace, &key, value).await.expect("Failed to set streaming test value");
    }
    
    // Stream all keys
    let mut stream = provider.list_stream(namespace, None).await.expect("Failed to create list stream");
    let mut count = 0;
    
    while let Some(result) = stream.next().await {
        let key = result.expect("Failed to get key from stream");
        assert!(key.starts_with("stream-key-"));
        count += 1;
    }
    
    assert_eq!(count, 100);
}