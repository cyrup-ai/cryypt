//! Test encryption and decryption roundtrip using README.md correct patterns

use cryypt_cipher::cipher::api::Cipher;

#[tokio::test]
async fn test_aes_encrypt_decrypt_roundtrip() {
    let key = vec![0u8; 32]; // 256-bit key
    let plaintext = b"Hello, World! This is a test message.";

    // Encrypt using README.md pattern with on_result
    let encrypted = Cipher::aes()
        .with_key(key.clone())
        .on_result(|result| match result {
            Ok(result) => result,
            Err(e) => {
                log::error!("Encryption failed: {e}");
                Vec::new()
            }
        })
        .encrypt(plaintext)
        .await; // Returns fully unwrapped Vec<u8>

    // Decrypt using README.md pattern with on_result
    let decrypted = Cipher::aes()
        .with_key(key)
        .on_result(|result| match result {
            Ok(result) => result,
            Err(e) => {
                log::error!("Decryption failed: {e}");
                Vec::new()
            }
        })
        .decrypt(encrypted)
        .await; // Returns fully unwrapped Vec<u8>

    assert_eq!(plaintext.to_vec(), decrypted);
}

#[tokio::test]
async fn test_chacha_encrypt_decrypt_roundtrip() {
    let key = vec![0u8; 32]; // 256-bit key
    let plaintext = b"Hello, ChaCha! This is another test message.";

    // Encrypt using README.md pattern with on_result
    let encrypted = Cipher::chachapoly()
        .with_key(key.clone())
        .on_result(|result| match result {
            Ok(result) => result,
            Err(e) => {
                log::error!("Encryption failed: {e}");
                Vec::new()
            }
        })
        .encrypt(plaintext)
        .await; // Returns fully unwrapped Vec<u8>

    // Decrypt using README.md pattern with on_result
    let decrypted = Cipher::chachapoly()
        .with_key(key)
        .on_result(|result| match result {
            Ok(result) => result,
            Err(e) => {
                log::error!("Decryption failed: {e}");
                Vec::new()
            }
        })
        .decrypt(encrypted)
        .await; // Returns fully unwrapped Vec<u8>

    assert_eq!(plaintext.to_vec(), decrypted);
}

#[tokio::test]
async fn test_aes_encrypt_to_base64_and_back() {
    use base64::Engine;

    let key = vec![0u8; 32];
    let plaintext = b"Base64 test message";

    // Encrypt using README.md pattern
    let encrypted = Cipher::aes()
        .with_key(key.clone())
        .on_result(|result| match result {
            Ok(result) => result,
            Err(e) => {
                log::error!("Encryption failed: {e}");
                Vec::new()
            }
        })
        .encrypt(plaintext)
        .await; // Returns fully unwrapped Vec<u8>

    // Use standard library for base64 encoding
    let base64_ciphertext = base64::engine::general_purpose::STANDARD.encode(&encrypted);

    // Decode base64 and decrypt using README.md pattern
    let ciphertext = base64::engine::general_purpose::STANDARD
        .decode(&base64_ciphertext)
        .expect("Base64 decode should succeed");

    let decrypted = Cipher::aes()
        .with_key(key)
        .on_result(|result| match result {
            Ok(result) => result,
            Err(e) => {
                log::error!("Decryption failed: {e}");
                Vec::new()
            }
        })
        .decrypt(ciphertext)
        .await; // Returns fully unwrapped Vec<u8>

    assert_eq!(plaintext.to_vec(), decrypted);
}

#[tokio::test]
async fn test_aes_encrypt_to_hex_and_back() {
    let key = vec![0u8; 32];
    let plaintext = b"Hex test message";

    // Encrypt using README.md pattern
    let encrypted = Cipher::aes()
        .with_key(key.clone())
        .on_result(|result| match result {
            Ok(result) => result,
            Err(e) => {
                log::error!("Encryption failed: {e}");
                Vec::new()
            }
        })
        .encrypt(plaintext)
        .await; // Returns fully unwrapped Vec<u8>

    // Use standard library for hex encoding
    let hex_ciphertext = hex::encode(&encrypted);

    // Decode hex and decrypt using README.md pattern
    let ciphertext = hex::decode(&hex_ciphertext).expect("Hex decode should succeed");

    let decrypted = Cipher::aes()
        .with_key(key)
        .on_result(|result| match result {
            Ok(result) => result,
            Err(e) => {
                log::error!("Decryption failed: {e}");
                Vec::new()
            }
        })
        .decrypt(ciphertext)
        .await; // Returns fully unwrapped Vec<u8>

    assert_eq!(plaintext.to_vec(), decrypted);
}
