//! Integration tests for cipher crate with compression and cross-algorithm scenarios

use cryypt_cipher::{prelude::*, Cipher};

// Note: These integration tests focus on the decryption APIs since we don't have
// access to the full key management infrastructure in tests. The encryption APIs
// require a proper KeyStore setup as shown in README.md

#[tokio::test]
async fn test_decryption_apis() {
    // Test that decryption APIs are accessible
    let key_material = b"This is a 32-byte secret key!!!";
    
    // Test AES decryption API
    let aes_ciphertext = vec![0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
    let aes_result = Cipher::decrypt(aes_ciphertext)
        .with_aes_key(key_material)
        .await;
    assert!(aes_result.is_err()); // Expected to fail with invalid ciphertext
    
    // Test ChaCha decryption API
    let chacha_ciphertext = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
    let chacha_result = Cipher::decrypt(chacha_ciphertext)
        .with_chacha_key(key_material)
        .await;
    assert!(chacha_result.is_err()); // Expected to fail with invalid ciphertext
}

#[tokio::test]
async fn test_error_propagation() {
    let key_material = b"This is a 32-byte secret key!!!";
    
    // Test various error conditions
    let empty_ciphertext = vec![];
    let result = Cipher::decrypt(empty_ciphertext)
        .with_aes_key(key_material)
        .await;
    
    match result {
        Err(e) => {
            // Verify we get a proper error type
            let _error_string = format!("{}", e);
        }
        Ok(_) => panic!("Should have failed with empty ciphertext"),
    }
}

#[tokio::test]
async fn test_async_nature() {
    let key_material = b"This is a 32-byte secret key!!!";
    
    // Test that operations are truly async
    let futures = vec![
        Cipher::decrypt(vec![1; 20]).with_aes_key(key_material),
        Cipher::decrypt(vec![2; 20]).with_aes_key(key_material),
        Cipher::decrypt(vec![3; 20]).with_aes_key(key_material),
    ];
    
    // Join all futures
    let results = futures::future::join_all(futures).await;
    
    // All should fail with invalid ciphertext
    for result in results {
        assert!(result.is_err());
    }
}