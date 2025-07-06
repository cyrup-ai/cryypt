//! Test that encryption returns EncodableResult correctly

use cryypt_cipher::cipher::api::Cipher;

#[tokio::test]
async fn test_aes_encryption_returns_encodable_result() {
    let key = vec![0u8; 32]; // 256-bit key
    let data = b"Hello, World!";
    
    // Test that encrypt returns something implementing AsyncEncryptionResult
    let encrypted = Cipher::aes()
        .with_key(key.clone())
        .encrypt(data)
        .await
        .expect("Encryption should succeed");
    
    // Test EncodableResult methods - first check properties
    assert!(!encrypted.is_empty());
    assert!(encrypted.len() > data.len()); // Should include nonce
    
    // Test hex encoding (consumes encrypted)
    let hex = encrypted.to_hex();
    assert!(!hex.is_empty());
    
    // Test base64 encoding with fresh encryption
    let encrypted = Cipher::aes()
        .with_key(key.clone())
        .encrypt(data)
        .await
        .expect("Encryption should succeed");
    let base64 = encrypted.to_base64(); 
    assert!(!base64.is_empty());
    
    // Test bytes conversion with fresh encryption
    let encrypted = Cipher::aes()
        .with_key(key)
        .encrypt(data)
        .await
        .expect("Encryption should succeed");
    let len = encrypted.len();
    let bytes = encrypted.to_bytes();
    assert_eq!(bytes.len(), len);
}

#[tokio::test]
async fn test_chacha_encryption_returns_encodable_result() {
    let key = vec![0u8; 32]; // 256-bit key
    let data = b"Hello, ChaCha!";
    
    // Test that encrypt returns something implementing AsyncEncryptionResult
    let encrypted = Cipher::chachapoly()
        .with_key(key.clone())
        .encrypt(data)
        .await
        .expect("Encryption should succeed");
    
    // Test EncodableResult methods - first check properties
    assert!(!encrypted.is_empty());
    assert!(encrypted.len() > data.len()); // Should include nonce
    
    // Test hex encoding (consumes encrypted)
    let hex = encrypted.to_hex();
    assert!(!hex.is_empty());
    
    // Test base64 encoding with fresh encryption
    let encrypted = Cipher::chachapoly()
        .with_key(key.clone())
        .encrypt(data)
        .await
        .expect("Encryption should succeed");
    let base64 = encrypted.to_base64();
    assert!(!base64.is_empty());
    
    // Test bytes conversion with fresh encryption
    let encrypted = Cipher::chachapoly()
        .with_key(key)
        .encrypt(data)
        .await
        .expect("Encryption should succeed");
    let len = encrypted.len();
    let bytes = encrypted.to_bytes();
    assert_eq!(bytes.len(), len);
}

#[tokio::test]
async fn test_encryption_with_result_handler() {
    let key = vec![0u8; 32];
    let data = b"Test data";
    
    let encrypted = Cipher::aes()
        .with_key(key)
        .on_result(|result| {
            match result {
                Ok(data) => Ok(data),
                Err(e) => {
                    eprintln!("Error in handler: {}", e);
                    Err(e)
                }
            }
        })
        .encrypt(data)
        .await
        .expect("Encryption should succeed");
    
    assert!(!encrypted.is_empty());
}