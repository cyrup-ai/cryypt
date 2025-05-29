//! Tests for cascade cipher implementation

use cyrup_crypt::{
    CascadeCipher, CryptError, EncryptedData,
    traits::{Cipher, Encryptor, Decryptor},
    key::StandardKeyId,
};
use std::sync::Arc;

#[tokio::test]
async fn test_cascade_encrypt_decrypt() {
    let cipher = CascadeCipher::new();
    let key_id = Arc::new(StandardKeyId::new("test-key", 1));
    
    let plaintext = b"Top Secret Cascade Algorithm Data".to_vec();
    
    // Encrypt
    let encrypted = cipher.encrypt(plaintext.clone(), Some(key_id.clone())).await.expect("Failed to encrypt plaintext with cascade cipher");
    
    // Verify it's cascade encrypted
    assert_eq!(encrypted.algorithm(), cyrup_crypt::cipher::CipherAlgorithm::Cascade);
    
    // Decrypt
    let decrypted = cipher.decrypt(encrypted, Some(key_id)).await.expect("Failed to decrypt cascade encrypted data");
    
    assert_eq!(plaintext, decrypted);
}

#[tokio::test]
async fn test_cascade_wrong_key() {
    let cipher = CascadeCipher::new();
    let key1 = Arc::new(StandardKeyId::new("key1", 1));
    let key2 = Arc::new(StandardKeyId::new("key2", 1));
    
    let plaintext = b"Secret".to_vec();
    
    // Encrypt with key1
    let encrypted = cipher.encrypt(plaintext, Some(key1)).await.expect("Failed to encrypt with key1");
    
    // Try to decrypt with key2 - should fail
    let result = cipher.decrypt(encrypted, Some(key2)).await;
    assert!(result.is_err());
    
    match result {
        Err(e) => {
            // Should be a decryption error
            assert!(matches!(e, CryptError::DecryptionFailed(_)));
        }
        Ok(_) => panic!("Should have failed to decrypt with wrong key"),
    }
}

#[tokio::test]
async fn test_cascade_with_aad() {
    let cipher = CascadeCipher::new();
    let key_id = Arc::new(StandardKeyId::new("test-key", 1));
    
    let plaintext = b"Secret message".to_vec();
    let aad = b"Additional authenticated data".to_vec();
    
    // Encrypt with AAD
    let encrypted = cipher.encrypt_with_aad(
        plaintext.clone(), 
        aad.clone(),
        Some(key_id.clone())
    ).await.expect("Failed to encrypt with AAD");
    
    // Verify AAD is stored
    assert_eq!(encrypted.aad(), Some(&aad[..]));
    
    // Decrypt - AAD should be automatically verified
    let decrypted = cipher.decrypt(encrypted.clone(), Some(key_id.clone())).await.expect("Failed to decrypt data with AAD");
    assert_eq!(plaintext, decrypted);
    
    // Try to decrypt with modified AAD - should fail
    let mut tampered = encrypted.clone();
    // This is a hack to test - in real use the EncryptedData should be immutable
    // We'd need to rebuild with different AAD
    let tampered_data = EncryptedData::builder()
        .ciphertext(encrypted.ciphertext().to_vec())
        .nonce(encrypted.nonce().to_vec())
        .algorithm(encrypted.algorithm())
        .key_id(encrypted.key_id())
        .aad(b"Tampered AAD".to_vec())
        .build()
        .expect("Failed to build tampered EncryptedData");
    
    let result = cipher.decrypt(tampered_data, Some(key_id)).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_cascade_no_key_provided() {
    let cipher = CascadeCipher::new();
    let plaintext = b"Test data".to_vec();
    
    // Try to encrypt without key - should fail
    let result = cipher.encrypt(plaintext, None).await;
    assert!(result.is_err());
    
    match result {
        Err(e) => {
            assert!(matches!(e, CryptError::InvalidKey(_)));
        }
        Ok(_) => panic!("Should have failed without key"),
    }
}

#[tokio::test]
async fn test_cascade_decrypt_with_embedded_key() {
    let cipher = CascadeCipher::new();
    let key_id = Arc::new(StandardKeyId::new("embedded-key", 1));
    
    let plaintext = b"Test with embedded key ID".to_vec();
    
    // Encrypt with key
    let encrypted = cipher.encrypt(plaintext.clone(), Some(key_id)).await.expect("Failed to encrypt with embedded key");
    
    // Decrypt without providing key - should use embedded key ID
    let decrypted = cipher.decrypt(encrypted, None).await.expect("Failed to decrypt using embedded key ID");
    
    assert_eq!(plaintext, decrypted);
}

#[tokio::test]
async fn test_cascade_large_data() {
    let cipher = CascadeCipher::new();
    let key_id = Arc::new(StandardKeyId::new("test-key", 1));
    
    // Create 1MB of test data
    let mut plaintext = Vec::with_capacity(1024 * 1024);
    for i in 0..1024 * 1024 {
        plaintext.push((i % 256) as u8);
    }
    
    // Encrypt
    let encrypted = cipher.encrypt(plaintext.clone(), Some(key_id.clone())).await.expect("Failed to encrypt large data");
    
    // Decrypt
    let decrypted = cipher.decrypt(encrypted, Some(key_id)).await.expect("Failed to decrypt large data");
    
    assert_eq!(plaintext, decrypted);
}

#[tokio::test]
async fn test_cascade_empty_data() {
    let cipher = CascadeCipher::new();
    let key_id = Arc::new(StandardKeyId::new("test-key", 1));
    
    let plaintext = Vec::new();
    
    // Encrypt empty data
    let encrypted = cipher.encrypt(plaintext.clone(), Some(key_id.clone())).await.expect("Failed to encrypt empty data");
    
    // Decrypt
    let decrypted = cipher.decrypt(encrypted, Some(key_id)).await.expect("Failed to decrypt empty data");
    
    assert_eq!(plaintext, decrypted);
}

#[tokio::test]
async fn test_cascade_algorithm_mismatch() {
    let cipher = CascadeCipher::new();
    let key_id = Arc::new(StandardKeyId::new("test-key", 1));
    
    // Create encrypted data with wrong algorithm
    let wrong_algo_data = EncryptedData::builder()
        .ciphertext(vec![1, 2, 3, 4])
        .nonce(vec![0; 24])
        .algorithm(cyrup_crypt::cipher::CipherAlgorithm::Aes256Gcm)
        .key_id_from(&*key_id)
        .build()
        .expect("Failed to build EncryptedData with wrong algorithm");
    
    // Try to decrypt - should fail with algorithm mismatch
    let result = cipher.decrypt(wrong_algo_data, Some(key_id)).await;
    assert!(result.is_err());
    
    match result {
        Err(e) => {
            assert!(matches!(e, CryptError::UnsupportedAlgorithm(_)));
        }
        Ok(_) => panic!("Should have failed with algorithm mismatch"),
    }
}

#[tokio::test]
async fn test_cascade_cipher_properties() {
    let cipher = CascadeCipher::new();
    
    // Test algorithm property
    assert_eq!(cipher.algorithm(), cyrup_crypt::cipher::CipherAlgorithm::Cascade);
    
    // Test key size - should be 64 bytes (32 for each layer)
    assert_eq!(cipher.key_size(), 64);
    
    // Test nonce size - should be 24 bytes (12 for each layer)
    assert_eq!(cipher.nonce_size(), 24);
    
    // Test tag size
    assert_eq!(cipher.tag_size(), 16);
    
    // Test default key ID
    let default_key = cipher.default_key_id().await.expect("Failed to get default key ID");
    assert_eq!(default_key.id(), "cascade-default");
    assert_eq!(default_key.version(), 1);
}

#[tokio::test]
async fn test_cascade_concurrent_operations() {
    use tokio::task::JoinSet;
    
    let cipher = Arc::new(CascadeCipher::new());
    let key_id = Arc::new(StandardKeyId::new("concurrent-key", 1));
    
    let mut tasks = JoinSet::new();
    
    // Spawn 10 concurrent encryption tasks
    for i in 0..10 {
        let cipher_clone = Arc::clone(&cipher);
        let key_clone = Arc::clone(&key_id);
        let data = format!("Concurrent test data {}", i).into_bytes();
        
        tasks.spawn(async move {
            let encrypted = cipher_clone.encrypt(data.clone(), Some(key_clone.clone())).await.expect("Failed to encrypt in concurrent task");
            let decrypted = cipher_clone.decrypt(encrypted, Some(key_clone)).await.expect("Failed to decrypt in concurrent task");
            assert_eq!(data, decrypted);
            i
        });
    }
    
    // Wait for all tasks to complete
    let mut completed = 0;
    while let Some(result) = tasks.join_next().await {
        result.expect("Concurrent task failed");
        completed += 1;
    }
    
    assert_eq!(completed, 10);
}