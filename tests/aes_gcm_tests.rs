//! Tests for AES-256-GCM cipher implementation

use cyrup_crypt::{
    CryptError, EncryptedData,
    cipher::{AesGcmCipher, CipherAlgorithm},
    traits::{Cipher, Encryptor, Decryptor},
    key::StandardKeyId,
};
use std::sync::Arc;

#[tokio::test]
async fn test_aes_gcm_encrypt_decrypt() {
    let cipher = AesGcmCipher::new();
    let key_id = Arc::new(StandardKeyId::new("test-key", 1));
    
    let plaintext = b"AES-256-GCM Test Data".to_vec();
    
    // Encrypt
    let encrypted = cipher.encrypt(plaintext.clone(), Some(key_id.clone())).await.expect("Failed to encrypt plaintext with AES-GCM");
    
    // Verify it's AES-GCM encrypted
    assert_eq!(encrypted.algorithm(), CipherAlgorithm::Aes256Gcm);
    assert_eq!(encrypted.nonce().len(), 12); // 96-bit nonce
    
    // Decrypt
    let decrypted = cipher.decrypt(encrypted, Some(key_id)).await.expect("Failed to decrypt AES-GCM encrypted data");
    
    assert_eq!(plaintext, decrypted);
}

#[tokio::test]
async fn test_aes_gcm_wrong_key() {
    let cipher = AesGcmCipher::new();
    let key1 = Arc::new(StandardKeyId::new("key1", 1));
    let key2 = Arc::new(StandardKeyId::new("key2", 1));
    
    let plaintext = b"Secret AES data".to_vec();
    
    // Encrypt with key1
    let encrypted = cipher.encrypt(plaintext, Some(key1)).await.expect("Failed to encrypt with key1");
    
    // Try to decrypt with key2 - should fail
    let result = cipher.decrypt(encrypted, Some(key2)).await;
    assert!(result.is_err());
    
    match result {
        Err(e) => {
            assert!(matches!(e, CryptError::DecryptionFailed(_)));
        }
        Ok(_) => panic!("Should have failed to decrypt with wrong key"),
    }
}

#[tokio::test]
async fn test_aes_gcm_with_aad() {
    let cipher = AesGcmCipher::new();
    let key_id = Arc::new(StandardKeyId::new("test-key", 1));
    
    let plaintext = b"Secret message".to_vec();
    let aad = b"Additional authenticated data for AES-GCM".to_vec();
    
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
    
    // Try to decrypt with tampered AAD
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
async fn test_aes_gcm_no_key_provided() {
    let cipher = AesGcmCipher::new();
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
async fn test_aes_gcm_decrypt_with_embedded_key() {
    let cipher = AesGcmCipher::new();
    let key_id = Arc::new(StandardKeyId::new("embedded-key", 1));
    
    let plaintext = b"Test with embedded key ID".to_vec();
    
    // Encrypt with key
    let encrypted = cipher.encrypt(plaintext.clone(), Some(key_id)).await.expect("Failed to encrypt with embedded key");
    
    // Decrypt without providing key - should use embedded key ID
    let decrypted = cipher.decrypt(encrypted, None).await.expect("Failed to decrypt using embedded key ID");
    
    assert_eq!(plaintext, decrypted);
}

#[tokio::test]
async fn test_aes_gcm_large_data() {
    let cipher = AesGcmCipher::new();
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
async fn test_aes_gcm_empty_data() {
    let cipher = AesGcmCipher::new();
    let key_id = Arc::new(StandardKeyId::new("test-key", 1));
    
    let plaintext = Vec::new();
    
    // Encrypt empty data
    let encrypted = cipher.encrypt(plaintext.clone(), Some(key_id.clone())).await.expect("Failed to encrypt empty data");
    
    // Decrypt
    let decrypted = cipher.decrypt(encrypted, Some(key_id)).await.expect("Failed to decrypt empty data");
    
    assert_eq!(plaintext, decrypted);
}

#[tokio::test]
async fn test_aes_gcm_algorithm_mismatch() {
    let cipher = AesGcmCipher::new();
    let key_id = Arc::new(StandardKeyId::new("test-key", 1));
    
    // Create encrypted data with wrong algorithm
    let wrong_algo_data = EncryptedData::builder()
        .ciphertext(vec![1, 2, 3, 4])
        .nonce(vec![0; 12])
        .algorithm(CipherAlgorithm::ChaCha20Poly1305)
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
async fn test_aes_gcm_invalid_nonce_size() {
    let cipher = AesGcmCipher::new();
    let key_id = Arc::new(StandardKeyId::new("test-key", 1));
    
    // Create encrypted data with wrong nonce size
    let wrong_nonce_data = EncryptedData::builder()
        .ciphertext(vec![1, 2, 3, 4])
        .nonce(vec![0; 16]) // Wrong size - should be 12
        .algorithm(CipherAlgorithm::Aes256Gcm)
        .key_id_from(&*key_id)
        .build()
        .expect("Failed to build EncryptedData with wrong nonce size");
    
    // Try to decrypt - should fail with invalid nonce size
    let result = cipher.decrypt(wrong_nonce_data, Some(key_id)).await;
    assert!(result.is_err());
    
    match result {
        Err(e) => {
            assert!(matches!(e, CryptError::InvalidNonceSize { expected: 12, actual: 16 }));
        }
        Ok(_) => panic!("Should have failed with invalid nonce size"),
    }
}

#[tokio::test]
async fn test_aes_gcm_cipher_properties() {
    let cipher = AesGcmCipher::new();
    
    // Test algorithm property
    assert_eq!(cipher.algorithm(), CipherAlgorithm::Aes256Gcm);
    
    // Test key size - should be 32 bytes for AES-256
    assert_eq!(cipher.key_size(), 32);
    
    // Test nonce size - should be 12 bytes (96 bits)
    assert_eq!(cipher.nonce_size(), 12);
    
    // Test tag size - should be 16 bytes (128 bits)
    assert_eq!(cipher.tag_size(), 16);
    
    // Test default key ID
    let default_key = cipher.default_key_id().await.expect("Failed to get default key ID");
    assert_eq!(default_key.id(), "aes-default");
    assert_eq!(default_key.version(), 1);
}

#[tokio::test]
async fn test_aes_gcm_verify_operation() {
    let cipher = AesGcmCipher::new();
    let key_id = Arc::new(StandardKeyId::new("test-key", 1));
    
    let plaintext = b"Test verification".to_vec();
    
    // Encrypt
    let encrypted = cipher.encrypt(plaintext, Some(key_id.clone())).await.expect("Failed to encrypt for verification test");
    
    // Verify should succeed for valid data
    cipher.verify(encrypted.clone(), Some(key_id.clone())).await.expect("Failed to verify valid encrypted data");
    
    // Create tampered data
    let mut tampered = encrypted.clone();
    let mut tampered_ciphertext = encrypted.ciphertext().to_vec();
    tampered_ciphertext[0] ^= 0xFF; // Flip some bits
    
    let tampered_data = EncryptedData::builder()
        .ciphertext(tampered_ciphertext)
        .nonce(encrypted.nonce().to_vec())
        .algorithm(encrypted.algorithm())
        .key_id(encrypted.key_id())
        .build()
        .expect("Failed to build tampered EncryptedData");
    
    // Verify should succeed (structure is valid, auth happens on decrypt)
    cipher.verify(tampered_data, Some(key_id)).await.expect("Failed to verify tampered data structure");
}

#[tokio::test]
async fn test_aes_gcm_concurrent_operations() {
    use tokio::task::JoinSet;
    
    let cipher = Arc::new(AesGcmCipher::new());
    let key_id = Arc::new(StandardKeyId::new("concurrent-key", 1));
    
    let mut tasks = JoinSet::new();
    
    // Spawn 10 concurrent encryption tasks
    for i in 0..10 {
        let cipher_clone = Arc::clone(&cipher);
        let key_clone = Arc::clone(&key_id);
        let data = format!("Concurrent AES-GCM test data {}", i).into_bytes();
        
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

#[tokio::test]
async fn test_aes_gcm_nonce_uniqueness() {
    let cipher = AesGcmCipher::new();
    let key_id = Arc::new(StandardKeyId::new("test-key", 1));
    
    let plaintext = b"Test nonce uniqueness".to_vec();
    
    // Encrypt the same data multiple times
    let mut nonces = Vec::new();
    for _ in 0..10 {
        let encrypted = cipher.encrypt(plaintext.clone(), Some(key_id.clone())).await.expect("Failed to encrypt for nonce uniqueness test");
        nonces.push(encrypted.nonce().to_vec());
    }
    
    // All nonces should be unique
    for i in 0..nonces.len() {
        for j in (i + 1)..nonces.len() {
            assert_ne!(nonces[i], nonces[j], "Nonces should be unique");
        }
    }
}