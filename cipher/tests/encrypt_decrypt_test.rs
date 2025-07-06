//! Test that encryption and decryption work together correctly

use cryypt_cipher::cipher::api::Cipher;

#[tokio::test]
async fn test_aes_encrypt_decrypt_roundtrip() {
    let key = vec![0u8; 32]; // 256-bit key
    let plaintext = b"Hello, World! This is a test message.";
    
    // Encrypt
    let encrypted = Cipher::aes()
        .with_key(key.clone())
        .encrypt(plaintext)
        .await
        .expect("Encryption should succeed");
    
    // Get bytes from EncodableResult
    let ciphertext = encrypted.to_bytes();
    
    // Decrypt
    let decrypted = Cipher::aes()
        .with_key(key)
        .decrypt(ciphertext)
        .await
        .expect("Decryption should succeed");
    
    assert_eq!(plaintext.to_vec(), decrypted);
}

#[tokio::test]
async fn test_chacha_encrypt_decrypt_roundtrip() {
    let key = vec![0u8; 32]; // 256-bit key
    let plaintext = b"Hello, ChaCha! This is another test message.";
    
    // Encrypt
    let encrypted = Cipher::chachapoly()
        .with_key(key.clone())
        .encrypt(plaintext)
        .await
        .expect("Encryption should succeed");
    
    // Get bytes from EncodableResult
    let ciphertext = encrypted.to_bytes();
    
    // Decrypt
    let decrypted = Cipher::chachapoly()
        .with_key(key)
        .decrypt(ciphertext)
        .await
        .expect("Decryption should succeed");
    
    assert_eq!(plaintext.to_vec(), decrypted);
}

#[tokio::test]
async fn test_aes_encrypt_to_base64_and_back() {
    let key = vec![0u8; 32];
    let plaintext = b"Base64 test message";
    
    // Encrypt and get base64
    let encrypted = Cipher::aes()
        .with_key(key.clone())
        .encrypt(plaintext)
        .await
        .expect("Encryption should succeed");
    
    let base64_ciphertext = encrypted.to_base64();
    
    // Decode base64 and decrypt
    use base64::Engine;
    let ciphertext = base64::engine::general_purpose::STANDARD
        .decode(&base64_ciphertext)
        .expect("Base64 decode should succeed");
    
    let decrypted = Cipher::aes()
        .with_key(key)
        .decrypt(ciphertext)
        .await
        .expect("Decryption should succeed");
    
    assert_eq!(plaintext.to_vec(), decrypted);
}

#[tokio::test]
async fn test_aes_encrypt_to_hex_and_back() {
    let key = vec![0u8; 32];
    let plaintext = b"Hex test message";
    
    // Encrypt and get hex
    let encrypted = Cipher::aes()
        .with_key(key.clone())
        .encrypt(plaintext)
        .await
        .expect("Encryption should succeed");
    
    let hex_ciphertext = encrypted.to_hex();
    
    // Decode hex and decrypt
    let ciphertext = hex::decode(&hex_ciphertext)
        .expect("Hex decode should succeed");
    
    let decrypted = Cipher::aes()
        .with_key(key)
        .decrypt(ciphertext)
        .await
        .expect("Decryption should succeed");
    
    assert_eq!(plaintext.to_vec(), decrypted);
}