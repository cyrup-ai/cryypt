//! Unit tests for AES builder functionality

use cryypt::prelude::*;
use std::fs;

#[tokio::test]
async fn test_aes_basic_encryption_decryption() -> Result<(), Box<dyn std::error::Error>> {
    let master_key = [1u8; 32];
    let test_data = b"Hello, AES World!";

    std::fs::create_dir_all("/tmp/aes_test_basic").ok();

    // Encrypt
    let ciphertext = Cipher::aes()
        .with_key(
            Key::size(256.bits())
                .with_store(FileKeyStore::at("/tmp/aes_test_basic").with_master_key(master_key))
                .with_namespace("test")
                .version(1),
        )
        .with_data(test_data)
        .encrypt()
        .await?;

    // Decrypt
    let plaintext = Cipher::aes()
        .with_key(
            Key::size(256.bits())
                .with_store(FileKeyStore::at("/tmp/aes_test_basic").with_master_key(master_key))
                .with_namespace("test")
                .version(1),
        )
        .with_ciphertext(ciphertext.to_bytes())
        .decrypt()
        .await?;

    assert_eq!(plaintext, test_data);

    std::fs::remove_dir_all("/tmp/aes_test_basic").ok();
    Ok(())
}

#[tokio::test]
async fn test_aes_with_text() -> Result<(), Box<dyn std::error::Error>> {
    let master_key = [2u8; 32];
    let test_text = "Hello, AES Text! 🔒";

    std::fs::create_dir_all("/tmp/aes_test_text").ok();

    // Encrypt text
    let ciphertext = Cipher::aes()
        .with_key(
            Key::size(256.bits())
                .with_store(FileKeyStore::at("/tmp/aes_test_text").with_master_key(master_key))
                .with_namespace("test")
                .version(1),
        )
        .with_text(test_text)
        .encrypt()
        .await?;

    // Decrypt and verify
    let plaintext = Cipher::aes()
        .with_key(
            Key::size(256.bits())
                .with_store(FileKeyStore::at("/tmp/aes_test_text").with_master_key(master_key))
                .with_namespace("test")
                .version(1),
        )
        .with_ciphertext(ciphertext.to_bytes())
        .decrypt()
        .await?;

    let decrypted_text = String::from_utf8(plaintext)?;
    assert_eq!(decrypted_text, test_text);

    std::fs::remove_dir_all("/tmp/aes_test_text").ok();
    Ok(())
}

#[tokio::test]
async fn test_aes_with_file() -> Result<(), Box<dyn std::error::Error>> {
    let master_key = [3u8; 32];
    let test_dir = "/tmp/aes_test_file";
    let test_file = format!("{}/input.txt", test_dir);
    let test_content = b"This is test file content for AES encryption!";

    std::fs::create_dir_all(test_dir)?;
    std::fs::write(&test_file, test_content)?;

    // Encrypt from file
    let ciphertext = Cipher::aes()
        .with_key(
            Key::size(256.bits())
                .with_store(FileKeyStore::at(test_dir).with_master_key(master_key))
                .with_namespace("test")
                .version(1),
        )
        .with_file(&test_file)
        .await?
        .encrypt()
        .await?;

    // Decrypt and verify
    let plaintext = Cipher::aes()
        .with_key(
            Key::size(256.bits())
                .with_store(FileKeyStore::at(test_dir).with_master_key(master_key))
                .with_namespace("test")
                .version(1),
        )
        .with_ciphertext(ciphertext.to_bytes())
        .decrypt()
        .await?;

    assert_eq!(plaintext, test_content);

    std::fs::remove_dir_all(test_dir).ok();
    Ok(())
}

#[tokio::test]
async fn test_aes_with_base64_input() -> Result<(), Box<dyn std::error::Error>> {
    let master_key = [4u8; 32];
    let original_data = b"Hello from base64!";
    let base64_data =
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, original_data);

    std::fs::create_dir_all("/tmp/aes_test_base64").ok();

    // Encrypt data from base64
    let ciphertext = Cipher::aes()
        .with_key(
            Key::size(256.bits())
                .with_store(FileKeyStore::at("/tmp/aes_test_base64").with_master_key(master_key))
                .with_namespace("test")
                .version(1),
        )
        .with_data_base64(&base64_data)?
        .encrypt()
        .await?;

    // Decrypt and verify
    let plaintext = Cipher::aes()
        .with_key(
            Key::size(256.bits())
                .with_store(FileKeyStore::at("/tmp/aes_test_base64").with_master_key(master_key))
                .with_namespace("test")
                .version(1),
        )
        .with_ciphertext(ciphertext.to_bytes())
        .decrypt()
        .await?;

    assert_eq!(plaintext, original_data);

    std::fs::remove_dir_all("/tmp/aes_test_base64").ok();
    Ok(())
}

#[tokio::test]
async fn test_aes_with_hex_input() -> Result<(), Box<dyn std::error::Error>> {
    let master_key = [5u8; 32];
    let original_data = b"Hello from hex!";
    let hex_data = hex::encode(original_data);

    std::fs::create_dir_all("/tmp/aes_test_hex").ok();

    // Encrypt data from hex
    let ciphertext = Cipher::aes()
        .with_key(
            Key::size(256.bits())
                .with_store(FileKeyStore::at("/tmp/aes_test_hex").with_master_key(master_key))
                .with_namespace("test")
                .version(1),
        )
        .with_data_hex(&hex_data)?
        .encrypt()
        .await?;

    // Decrypt and verify
    let plaintext = Cipher::aes()
        .with_key(
            Key::size(256.bits())
                .with_store(FileKeyStore::at("/tmp/aes_test_hex").with_master_key(master_key))
                .with_namespace("test")
                .version(1),
        )
        .with_ciphertext(ciphertext.to_bytes())
        .decrypt()
        .await?;

    assert_eq!(plaintext, original_data);

    std::fs::remove_dir_all("/tmp/aes_test_hex").ok();
    Ok(())
}

#[tokio::test]
async fn test_aes_ciphertext_from_base64() -> Result<(), Box<dyn std::error::Error>> {
    let master_key = [6u8; 32];
    let test_data = b"Hello, base64 ciphertext!";

    std::fs::create_dir_all("/tmp/aes_test_cipher_base64").ok();

    // First encrypt to get ciphertext
    let ciphertext = Cipher::aes()
        .with_key(
            Key::size(256.bits())
                .with_store(
                    FileKeyStore::at("/tmp/aes_test_cipher_base64").with_master_key(master_key),
                )
                .with_namespace("test")
                .version(1),
        )
        .with_data(test_data)
        .encrypt()
        .await?;

    let base64_ciphertext = ciphertext.to_base64();

    // Decrypt from base64 ciphertext
    let plaintext = Cipher::aes()
        .with_key(
            Key::size(256.bits())
                .with_store(
                    FileKeyStore::at("/tmp/aes_test_cipher_base64").with_master_key(master_key),
                )
                .with_namespace("test")
                .version(1),
        )
        .with_ciphertext_base64(&base64_ciphertext)?
        .decrypt()
        .await?;

    assert_eq!(plaintext, test_data);

    std::fs::remove_dir_all("/tmp/aes_test_cipher_base64").ok();
    Ok(())
}

#[tokio::test]
async fn test_aes_ciphertext_from_hex() -> Result<(), Box<dyn std::error::Error>> {
    let master_key = [7u8; 32];
    let test_data = b"Hello, hex ciphertext!";

    std::fs::create_dir_all("/tmp/aes_test_cipher_hex").ok();

    // First encrypt to get ciphertext
    let ciphertext = Cipher::aes()
        .with_key(
            Key::size(256.bits())
                .with_store(
                    FileKeyStore::at("/tmp/aes_test_cipher_hex").with_master_key(master_key),
                )
                .with_namespace("test")
                .version(1),
        )
        .with_data(test_data)
        .encrypt()
        .await?;

    let hex_ciphertext = ciphertext.to_hex();

    // Decrypt from hex ciphertext
    let plaintext = Cipher::aes()
        .with_key(
            Key::size(256.bits())
                .with_store(
                    FileKeyStore::at("/tmp/aes_test_cipher_hex").with_master_key(master_key),
                )
                .with_namespace("test")
                .version(1),
        )
        .with_ciphertext_hex(&hex_ciphertext)?
        .decrypt()
        .await?;

    assert_eq!(plaintext, test_data);

    std::fs::remove_dir_all("/tmp/aes_test_cipher_hex").ok();
    Ok(())
}

#[tokio::test]
async fn test_aes_ciphertext_from_file() -> Result<(), Box<dyn std::error::Error>> {
    let master_key = [8u8; 32];
    let test_dir = "/tmp/aes_test_cipher_file";
    let ciphertext_file = format!("{}/ciphertext.bin", test_dir);
    let test_data = b"Hello, ciphertext file!";

    std::fs::create_dir_all(test_dir)?;

    // First encrypt and save to file
    let ciphertext = Cipher::aes()
        .with_key(
            Key::size(256.bits())
                .with_store(FileKeyStore::at(test_dir).with_master_key(master_key))
                .with_namespace("test")
                .version(1),
        )
        .with_data(test_data)
        .encrypt()
        .await?;

    ciphertext.to_file(&ciphertext_file).await?;

    // Decrypt from file
    let plaintext = Cipher::aes()
        .with_key(
            Key::size(256.bits())
                .with_store(FileKeyStore::at(test_dir).with_master_key(master_key))
                .with_namespace("test")
                .version(1),
        )
        .with_ciphertext_file(&ciphertext_file)
        .await?
        .decrypt()
        .await?;

    assert_eq!(plaintext, test_data);

    std::fs::remove_dir_all(test_dir).ok();
    Ok(())
}

#[tokio::test]
async fn test_aes_large_data() -> Result<(), Box<dyn std::error::Error>> {
    let master_key = [9u8; 32];
    let large_data: Vec<u8> = (0..10000).map(|i| (i % 256) as u8).collect();

    std::fs::create_dir_all("/tmp/aes_test_large").ok();

    // Encrypt large data
    let ciphertext = Cipher::aes()
        .with_key(
            Key::size(256.bits())
                .with_store(FileKeyStore::at("/tmp/aes_test_large").with_master_key(master_key))
                .with_namespace("test")
                .version(1),
        )
        .with_data(large_data.clone())
        .encrypt()
        .await?;

    // Decrypt and verify
    let plaintext = Cipher::aes()
        .with_key(
            Key::size(256.bits())
                .with_store(FileKeyStore::at("/tmp/aes_test_large").with_master_key(master_key))
                .with_namespace("test")
                .version(1),
        )
        .with_ciphertext(ciphertext.to_bytes())
        .decrypt()
        .await?;

    assert_eq!(plaintext, large_data);
    assert_eq!(plaintext.len(), 10000);

    std::fs::remove_dir_all("/tmp/aes_test_large").ok();
    Ok(())
}

#[tokio::test]
async fn test_aes_empty_data() -> Result<(), Box<dyn std::error::Error>> {
    let master_key = [10u8; 32];
    let empty_data: Vec<u8> = Vec::new();

    std::fs::create_dir_all("/tmp/aes_test_empty").ok();

    // Encrypt empty data
    let ciphertext = Cipher::aes()
        .with_key(
            Key::size(256.bits())
                .with_store(FileKeyStore::at("/tmp/aes_test_empty").with_master_key(master_key))
                .with_namespace("test")
                .version(1),
        )
        .with_data(empty_data.clone())
        .encrypt()
        .await?;

    // Ciphertext should not be empty (contains nonce + auth tag)
    assert!(!ciphertext.to_bytes().is_empty());

    // Decrypt and verify
    let plaintext = Cipher::aes()
        .with_key(
            Key::size(256.bits())
                .with_store(FileKeyStore::at("/tmp/aes_test_empty").with_master_key(master_key))
                .with_namespace("test")
                .version(1),
        )
        .with_ciphertext(ciphertext.to_bytes())
        .decrypt()
        .await?;

    assert_eq!(plaintext, empty_data);
    assert!(plaintext.is_empty());

    std::fs::remove_dir_all("/tmp/aes_test_empty").ok();
    Ok(())
}

#[tokio::test]
async fn test_aes_different_keys() -> Result<(), Box<dyn std::error::Error>> {
    let master_key1 = [11u8; 32];
    let master_key2 = [12u8; 32];
    let test_data = b"Different keys test";

    std::fs::create_dir_all("/tmp/aes_test_diff_keys").ok();

    // Encrypt with first key
    let ciphertext = Cipher::aes()
        .with_key(
            Key::size(256.bits())
                .with_store(
                    FileKeyStore::at("/tmp/aes_test_diff_keys").with_master_key(master_key1),
                )
                .with_namespace("test")
                .version(1),
        )
        .with_data(test_data)
        .encrypt()
        .await?;

    // Try to decrypt with different key - should fail
    let result = Cipher::aes()
        .with_key(
            Key::size(256.bits())
                .with_store(
                    FileKeyStore::at("/tmp/aes_test_diff_keys").with_master_key(master_key2),
                )
                .with_namespace("test")
                .version(1),
        )
        .with_ciphertext(ciphertext.to_bytes())
        .decrypt()
        .await;

    assert!(result.is_err());

    std::fs::remove_dir_all("/tmp/aes_test_diff_keys").ok();
    Ok(())
}

#[tokio::test]
async fn test_aes_binary_data() -> Result<(), Box<dyn std::error::Error>> {
    let master_key = [13u8; 32];
    let binary_data = vec![0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD, 0x80, 0x7F];

    std::fs::create_dir_all("/tmp/aes_test_binary").ok();

    // Encrypt binary data
    let ciphertext = Cipher::aes()
        .with_key(
            Key::size(256.bits())
                .with_store(FileKeyStore::at("/tmp/aes_test_binary").with_master_key(master_key))
                .with_namespace("test")
                .version(1),
        )
        .with_data(binary_data.clone())
        .encrypt()
        .await?;

    // Decrypt and verify
    let plaintext = Cipher::aes()
        .with_key(
            Key::size(256.bits())
                .with_store(FileKeyStore::at("/tmp/aes_test_binary").with_master_key(master_key))
                .with_namespace("test")
                .version(1),
        )
        .with_ciphertext(ciphertext.to_bytes())
        .decrypt()
        .await?;

    assert_eq!(plaintext, binary_data);

    std::fs::remove_dir_all("/tmp/aes_test_binary").ok();
    Ok(())
}

#[tokio::test]
async fn test_aes_invalid_ciphertext_too_short() {
    let master_key = [14u8; 32];
    let short_ciphertext = vec![0x01, 0x02]; // Too short (< 12 bytes for nonce)

    std::fs::create_dir_all("/tmp/aes_test_invalid").ok();

    let result = Cipher::aes()
        .with_key(
            Key::size(256.bits())
                .with_store(FileKeyStore::at("/tmp/aes_test_invalid").with_master_key(master_key))
                .with_namespace("test")
                .version(1),
        )
        .with_ciphertext(short_ciphertext)
        .decrypt()
        .await;

    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        cryypt::CryptError::DecryptionFailed(_)
    ));

    std::fs::remove_dir_all("/tmp/aes_test_invalid").ok();
}

#[tokio::test]
async fn test_aes_invalid_ciphertext_corrupted() {
    let master_key = [15u8; 32];
    let test_data = b"Original data";

    std::fs::create_dir_all("/tmp/aes_test_corrupted").ok();

    // First encrypt valid data
    let mut ciphertext = Cipher::aes()
        .with_key(
            Key::size(256.bits())
                .with_store(FileKeyStore::at("/tmp/aes_test_corrupted").with_master_key(master_key))
                .with_namespace("test")
                .version(1),
        )
        .with_data(test_data)
        .encrypt()
        .await
        .unwrap()
        .to_bytes();

    // Corrupt the ciphertext
    ciphertext[20] ^= 0xFF; // Flip some bits

    // Try to decrypt - should fail
    let result = Cipher::aes()
        .with_key(
            Key::size(256.bits())
                .with_store(FileKeyStore::at("/tmp/aes_test_corrupted").with_master_key(master_key))
                .with_namespace("test")
                .version(1),
        )
        .with_ciphertext(ciphertext)
        .decrypt()
        .await;

    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        cryypt::CryptError::DecryptionFailed(_)
    ));

    std::fs::remove_dir_all("/tmp/aes_test_corrupted").ok();
}
