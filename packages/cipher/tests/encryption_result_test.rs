//! Test encryption using README.md correct patterns

use cryypt_cipher::cipher::api::Cipher;

#[tokio::test]
async fn test_aes_encryption_with_on_result() {
    use base64::Engine;

    let key = vec![0u8; 32]; // 256-bit key
    let data = b"Hello, World!";

    // README.md pattern: on_result with sexy syntax
    let encrypted = Cipher::aes()
        .with_key(key.clone())
        .on_result(|result| match result {
            Ok(result) => result,
            Err(e) => {
                log::error!("Cipher operation failed: {e}");
                Vec::new()
            }
        })
        .encrypt(data)
        .await; // Returns fully unwrapped value - no .expect() needed

    // Test Vec<u8> properties - README.md shows encrypt returns Vec<u8>
    assert!(!encrypted.is_empty());
    assert!(encrypted.len() > data.len()); // Should include nonce

    // Test hex encoding using standard library
    let hex = hex::encode(&encrypted);
    assert!(!hex.is_empty());

    // Test base64 encoding using standard library
    let base64 = base64::engine::general_purpose::STANDARD.encode(&encrypted);
    assert!(!base64.is_empty());
}

#[tokio::test]
async fn test_chacha_encryption_with_on_result() {
    use base64::Engine;

    let key = vec![0u8; 32]; // 256-bit key
    let data = b"Hello, ChaCha!";

    // README.md pattern: on_result with sexy syntax
    let encrypted = Cipher::chachapoly()
        .with_key(key.clone())
        .on_result(|result| match result {
            Ok(result) => result,
            Err(e) => {
                log::error!("Cipher operation failed: {e}");
                Vec::new()
            }
        })
        .encrypt(data)
        .await; // Returns fully unwrapped value - no .expect() needed

    // Test Vec<u8> properties - README.md shows encrypt returns Vec<u8>
    assert!(!encrypted.is_empty());
    assert!(encrypted.len() > data.len()); // Should include nonce

    // Test hex encoding using standard library
    let hex = hex::encode(&encrypted);
    assert!(!hex.is_empty());

    // Test base64 encoding using standard library
    let base64 = base64::engine::general_purpose::STANDARD.encode(&encrypted);
    assert!(!base64.is_empty());
}

#[tokio::test]
async fn test_error_handling_with_on_result() {
    let invalid_key = vec![0u8; 16]; // Invalid key size to test error handling
    let data = b"Test data";

    // README.md pattern: on_result handler with error handling
    let result = Cipher::aes()
        .with_key(invalid_key)
        .on_result(|result| {
            match result {
                Ok(data) => data, // Return Vec<u8> directly - NotResult type
                Err(e) => {
                    // This should be called due to invalid key size
                    eprintln!("Expected error caught: {e}");
                    vec![42, 42, 42] // Return specific error marker
                }
            }
        })
        .encrypt(data)
        .await; // No .expect() - returns fully unwrapped value per README.md

    // Should return our error marker since key was invalid
    assert_eq!(result, vec![42, 42, 42]);
}
