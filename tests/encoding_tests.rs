//! Tests for encoding/decoding functionality

use cryypt::prelude::*;

#[tokio::test]
async fn test_base64_encoding() -> Result<(), Box<dyn std::error::Error>> {
    let master_key = [1u8; 32];

    // Encrypt and get base64
    let base64_result = Cipher::aes()
        .with_key(
            Key::size(256.bits())
                .with_store(FileKeyStore::at("/tmp/encoding_test_base64").with_master_key(master_key))
                .with_namespace("test")
                .version(1),
        )
        .with_data(b"Hello, World!")
        .encrypt()
        .await?
        .to_base64();

    // Decrypt from base64
    let plaintext = Cipher::aes()
        .with_key(
            Key::size(256.bits())
                .with_store(FileKeyStore::at("/tmp/encoding_test_base64").with_master_key(master_key))
                .with_namespace("test")
                .version(1),
        )
        .with_ciphertext_base64(&base64_result)?
        .decrypt()
        .await?;

    assert_eq!(plaintext, b"Hello, World!");
    std::fs::remove_dir_all("/tmp/encoding_test_base64").ok();
    Ok(())
}

#[tokio::test]
async fn test_hex_encoding() -> Result<(), Box<dyn std::error::Error>> {
    let master_key = [2u8; 32];

    // Encrypt and get hex
    let hex_result = Cipher::aes()
        .with_key(
            Key::size(256.bits())
                .with_store(FileKeyStore::at("/tmp/encoding_test_hex").with_master_key(master_key))
                .with_namespace("test")
                .version(1),
        )
        .with_data(b"Hello, World!")
        .encrypt()
        .await?
        .to_hex();

    // Decrypt from hex
    let plaintext = Cipher::aes()
        .with_key(
            Key::size(256.bits())
                .with_store(FileKeyStore::at("/tmp/encoding_test_hex").with_master_key(master_key))
                .with_namespace("test")
                .version(1),
        )
        .with_ciphertext_hex(&hex_result)?
        .decrypt()
        .await?;

    assert_eq!(plaintext, b"Hello, World!");
    std::fs::remove_dir_all("/tmp/encoding_test_hex").ok();
    Ok(())
}

#[tokio::test]
async fn test_string_methods() -> Result<(), Box<dyn std::error::Error>> {
    let master_key = [3u8; 32];

    // Encrypt text and get as string
    let result = Cipher::aes()
        .with_key(
            Key::size(256.bits())
                .with_store(FileKeyStore::at("/tmp/encoding_test_string").with_master_key(master_key))
                .with_namespace("test")
                .version(1),
        )
        .with_text("Hello, 世界!")
        .encrypt()
        .await?;

    // Decrypt and get as string
    let decrypted_text = Cipher::aes()
        .with_key(
            Key::size(256.bits())
                .with_store(FileKeyStore::at("/tmp/encoding_test_string").with_master_key(master_key))
                .with_namespace("test")
                .version(1),
        )
        .with_ciphertext(result.to_bytes())
        .decrypt()
        .await?;

    let text = String::from_utf8(decrypted_text)?;
    assert_eq!(text, "Hello, 世界!");

    std::fs::remove_dir_all("/tmp/encoding_test_string").ok();
    Ok(())
}

#[tokio::test]
async fn test_file_operations() -> Result<(), Box<dyn std::error::Error>> {
    use std::fs;
    use std::path::Path;

    let master_key = [4u8; 32];
    let test_data = b"This is test file content for encryption!";
    
    // Create test directories
    fs::create_dir_all("/tmp/encoding_test_files")?;
    
    // Write test data to file
    let input_file = "/tmp/encoding_test_files/input.txt";
    let encrypted_file = "/tmp/encoding_test_files/encrypted.bin";
    fs::write(input_file, test_data)?;

    // Encrypt from file and save to file
    let encrypted_result = Cipher::aes()
        .with_key(
            Key::size(256.bits())
                .with_store(FileKeyStore::at("/tmp/encoding_test_files").with_master_key(master_key))
                .with_namespace("test")
                .version(1),
        )
        .with_file(input_file)
        .await?
        .encrypt()
        .await?;

    // Save encrypted data to file
    encrypted_result.to_file(encrypted_file).await?;

    // Decrypt from file
    let plaintext = Cipher::aes()
        .with_key(
            Key::size(256.bits())
                .with_store(FileKeyStore::at("/tmp/encoding_test_files").with_master_key(master_key))
                .with_namespace("test")
                .version(1),
        )
        .with_ciphertext_file(encrypted_file)
        .await?
        .decrypt()
        .await?;

    assert_eq!(plaintext, test_data);

    // Cleanup
    fs::remove_dir_all("/tmp/encoding_test_files").ok();
    Ok(())
}

#[tokio::test]
async fn test_data_encoding_methods() -> Result<(), Box<dyn std::error::Error>> {
    let master_key = [5u8; 32];

    // Test data from base64
    let original_data = b"Hello from base64!";
    let base64_data = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, original_data);

    let ciphertext = Cipher::aes()
        .with_key(
            Key::size(256.bits())
                .with_store(FileKeyStore::at("/tmp/encoding_test_data").with_master_key(master_key))
                .with_namespace("test")
                .version(1),
        )
        .with_data_base64(&base64_data)?
        .encrypt()
        .await?;

    let plaintext = Cipher::aes()
        .with_key(
            Key::size(256.bits())
                .with_store(FileKeyStore::at("/tmp/encoding_test_data").with_master_key(master_key))
                .with_namespace("test")
                .version(1),
        )
        .with_ciphertext(ciphertext.to_bytes())
        .decrypt()
        .await?;

    assert_eq!(plaintext, original_data);

    // Test data from hex
    let hex_data = hex::encode(original_data);
    let ciphertext = Cipher::aes()
        .with_key(
            Key::size(256.bits())
                .with_store(FileKeyStore::at("/tmp/encoding_test_data").with_master_key(master_key))
                .with_namespace("test")
                .version(1),
        )
        .with_data_hex(&hex_data)?
        .encrypt()
        .await?;

    let plaintext = Cipher::aes()
        .with_key(
            Key::size(256.bits())
                .with_store(FileKeyStore::at("/tmp/encoding_test_data").with_master_key(master_key))
                .with_namespace("test")
                .version(1),
        )
        .with_ciphertext(ciphertext.to_bytes())
        .decrypt()
        .await?;

    assert_eq!(plaintext, original_data);

    std::fs::remove_dir_all("/tmp/encoding_test_data").ok();
    Ok(())
}