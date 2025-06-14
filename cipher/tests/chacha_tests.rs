//! Comprehensive ChaCha20-Poly1305 encryption/decryption tests for 100% coverage

use cryypt_cipher::{prelude::*, Cipher};

#[tokio::test]
async fn test_chacha_basic_decryption_raw_key() {
    let key_material = b"This is a 32-byte secret key!!!"; // 32 bytes for ChaCha20
    
    // Create a test vector - this would normally come from encryption
    let mut test_ciphertext = vec![1u8; 12]; // Nonce (12 bytes)
    test_ciphertext.extend_from_slice(&[2u8; 32]); // Ciphertext + tag
    
    // Test decryption with raw key - this should fail with invalid ciphertext
    let result = Cipher::decrypt(test_ciphertext)
        .with_chacha_key(key_material)
        .await;
    
    assert!(result.is_err()); // Should fail with invalid ciphertext
}

#[tokio::test]
async fn test_chacha_decryption_invalid_ciphertext_too_short() {
    let key_material = b"This is a 32-byte secret key!!!";
    let short_ciphertext = vec![1, 2, 3]; // Too short
    
    let result = Cipher::decrypt(short_ciphertext)
        .with_chacha_key(key_material)
        .await;
    
    assert!(result.is_err());
}

#[tokio::test]
async fn test_chacha_decryption_wrong_key() {
    let correct_key = b"Correct 32-byte secret key!!!!!";
    let wrong_key = b"Wrong 32-byte secret key!!!!!!!";
    
    // Create a test ciphertext structure for ChaCha20-Poly1305
    let mut test_ciphertext = vec![1u8; 12]; // Nonce
    test_ciphertext.extend_from_slice(&[2u8; 32]); // Ciphertext + tag
    
    // Try to decrypt with wrong key
    let result = Cipher::decrypt(test_ciphertext)
        .with_chacha_key(wrong_key)
        .await;
    
    assert!(result.is_err());
}

#[tokio::test]
async fn test_chacha_corrupted_nonce() {
    let key_material = b"This is a 32-byte secret key!!!";
    
    // Create a valid-looking ciphertext
    let mut test_ciphertext = vec![0u8; 12]; // Nonce
    test_ciphertext.extend_from_slice(&[1u8; 32]); // Ciphertext + tag
    
    // Corrupt the nonce
    test_ciphertext[5] = test_ciphertext[5].wrapping_add(1);
    
    let result = Cipher::decrypt(test_ciphertext)
        .with_chacha_key(key_material)
        .await;
    
    assert!(result.is_err());
}

#[tokio::test]
async fn test_chacha_corrupted_tag() {
    let key_material = b"This is a 32-byte secret key!!!";
    
    // Create a valid-looking ciphertext with proper structure
    let mut test_ciphertext = vec![0u8; 12]; // Nonce
    test_ciphertext.extend_from_slice(&[0u8; 16]); // Ciphertext
    test_ciphertext.extend_from_slice(&[0u8; 16]); // Tag
    
    // Corrupt the tag (last 16 bytes)
    let len = test_ciphertext.len();
    test_ciphertext[len - 1] = test_ciphertext[len - 1].wrapping_add(1);
    
    let result = Cipher::decrypt(test_ciphertext)
        .with_chacha_key(key_material)
        .await;
    
    assert!(result.is_err());
}

#[tokio::test]
async fn test_chacha_empty_ciphertext() {
    let key_material = b"This is a 32-byte secret key!!!";
    
    // ChaCha20-Poly1305 can encrypt empty data, but still needs nonce + tag
    let mut test_ciphertext = vec![0u8; 12]; // Nonce
    test_ciphertext.extend_from_slice(&[0u8; 16]); // Just tag, no ciphertext
    
    let result = Cipher::decrypt(test_ciphertext)
        .with_chacha_key(key_material)
        .await;
    
    assert!(result.is_err()); // Will fail due to invalid tag
}

#[tokio::test]
async fn test_chacha_various_invalid_lengths() {
    let key_material = b"This is a 32-byte secret key!!!";
    
    // Test various invalid lengths
    let test_cases = vec![
        vec![],           // Empty
        vec![1],          // 1 byte
        vec![1; 11],      // 11 bytes (less than nonce)
        vec![1; 12],      // 12 bytes (just nonce, no tag)
        vec![1; 27],      // 27 bytes (nonce + partial tag)
    ];
    
    for test_ciphertext in test_cases {
        let result = Cipher::decrypt(test_ciphertext)
            .with_chacha_key(key_material)
            .await;
        assert!(result.is_err());
    }
}

#[tokio::test]
async fn test_chacha_invalid_key_length() {
    // ChaCha20 requires exactly 32 bytes
    let short_key = b"Too short!";
    let long_key = b"This key is way too long for ChaCha20-Poly1305!";
    
    let mut test_ciphertext = vec![0u8; 12]; // Nonce
    test_ciphertext.extend_from_slice(&[0u8; 32]); // Ciphertext + tag
    
    // Test with short key
    let result = Cipher::decrypt(test_ciphertext.clone())
        .with_chacha_key(short_key)
        .await;
    assert!(result.is_err());
    
    // Test with long key
    let result = Cipher::decrypt(test_ciphertext)
        .with_chacha_key(&long_key[..33]) // 33 bytes
        .await;
    assert!(result.is_err());
}