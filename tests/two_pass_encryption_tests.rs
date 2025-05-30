//! Unit tests for two-pass encryption/decryption functionality

use cryypt::prelude::*;
use std::fs;

#[tokio::test]
async fn test_aes_then_chacha_two_pass() -> Result<(), Box<dyn std::error::Error>> {
    let master_key = [1u8; 32];
    let test_data = b"Two-pass encryption test data";

    std::fs::create_dir_all("/tmp/two_pass_test_aes_chacha").ok();

    // Encrypt: AES first, then ChaCha
    let ciphertext = Cipher::aes()
        .with_key(
            Key::size(256.bits())
                .with_store(
                    FileKeyStore::at("/tmp/two_pass_test_aes_chacha").with_master_key(master_key),
                )
                .with_namespace("test")
                .version(1),
        )
        .with_data(test_data)
        .second_pass(
            Cipher::chachapoly().with_key(
                Key::size(256.bits())
                    .with_store(
                        FileKeyStore::at("/tmp/two_pass_test_aes_chacha")
                            .with_master_key(master_key),
                    )
                    .with_namespace("test")
                    .version(2),
            ),
        )
        .encrypt()
        .await?;

    // Decrypt: ChaCha first (reverse order), then AES
    let plaintext = Cipher::chachapoly()
        .with_key(
            Key::size(256.bits())
                .with_store(
                    FileKeyStore::at("/tmp/two_pass_test_aes_chacha").with_master_key(master_key),
                )
                .with_namespace("test")
                .version(2),
        )
        .with_ciphertext(ciphertext.to_bytes())
        .second_pass(
            Cipher::aes().with_key(
                Key::size(256.bits())
                    .with_store(
                        FileKeyStore::at("/tmp/two_pass_test_aes_chacha")
                            .with_master_key(master_key),
                    )
                    .with_namespace("test")
                    .version(1),
            ),
        )
        .decrypt()
        .await?;

    assert_eq!(plaintext, test_data);

    std::fs::remove_dir_all("/tmp/two_pass_test_aes_chacha").ok();
    Ok(())
}

#[tokio::test]
async fn test_chacha_then_aes_two_pass() -> Result<(), Box<dyn std::error::Error>> {
    let master_key = [2u8; 32];
    let test_data = b"ChaCha then AES two-pass test";

    std::fs::create_dir_all("/tmp/two_pass_test_chacha_aes").ok();

    // Encrypt: ChaCha first, then AES
    let ciphertext = Cipher::chachapoly()
        .with_key(
            Key::size(256.bits())
                .with_store(
                    FileKeyStore::at("/tmp/two_pass_test_chacha_aes").with_master_key(master_key),
                )
                .with_namespace("test")
                .version(1),
        )
        .with_data(test_data)
        .second_pass(
            Cipher::aes().with_key(
                Key::size(256.bits())
                    .with_store(
                        FileKeyStore::at("/tmp/two_pass_test_chacha_aes")
                            .with_master_key(master_key),
                    )
                    .with_namespace("test")
                    .version(2),
            ),
        )
        .encrypt()
        .await?;

    // Decrypt: AES first (reverse order), then ChaCha
    let plaintext = Cipher::aes()
        .with_key(
            Key::size(256.bits())
                .with_store(
                    FileKeyStore::at("/tmp/two_pass_test_chacha_aes").with_master_key(master_key),
                )
                .with_namespace("test")
                .version(2),
        )
        .with_ciphertext(ciphertext.to_bytes())
        .second_pass(
            Cipher::chachapoly().with_key(
                Key::size(256.bits())
                    .with_store(
                        FileKeyStore::at("/tmp/two_pass_test_chacha_aes")
                            .with_master_key(master_key),
                    )
                    .with_namespace("test")
                    .version(1),
            ),
        )
        .decrypt()
        .await?;

    assert_eq!(plaintext, test_data);

    std::fs::remove_dir_all("/tmp/two_pass_test_chacha_aes").ok();
    Ok(())
}

#[tokio::test]
async fn test_aes_double_pass() -> Result<(), Box<dyn std::error::Error>> {
    let master_key = [3u8; 32];
    let test_data = b"AES double-pass encryption test";

    std::fs::create_dir_all("/tmp/two_pass_test_aes_double").ok();

    // Encrypt: AES with first key, then AES with second key
    let ciphertext = Cipher::aes()
        .with_key(
            Key::size(256.bits())
                .with_store(
                    FileKeyStore::at("/tmp/two_pass_test_aes_double").with_master_key(master_key),
                )
                .with_namespace("test")
                .version(1),
        )
        .with_data(test_data)
        .second_pass(
            Cipher::aes().with_key(
                Key::size(256.bits())
                    .with_store(
                        FileKeyStore::at("/tmp/two_pass_test_aes_double")
                            .with_master_key(master_key),
                    )
                    .with_namespace("test")
                    .version(2),
            ),
        )
        .encrypt()
        .await?;

    // Decrypt: AES with second key first, then AES with first key
    let plaintext = Cipher::aes()
        .with_key(
            Key::size(256.bits())
                .with_store(
                    FileKeyStore::at("/tmp/two_pass_test_aes_double").with_master_key(master_key),
                )
                .with_namespace("test")
                .version(2),
        )
        .with_ciphertext(ciphertext.to_bytes())
        .second_pass(
            Cipher::aes().with_key(
                Key::size(256.bits())
                    .with_store(
                        FileKeyStore::at("/tmp/two_pass_test_aes_double")
                            .with_master_key(master_key),
                    )
                    .with_namespace("test")
                    .version(1),
            ),
        )
        .decrypt()
        .await?;

    assert_eq!(plaintext, test_data);

    std::fs::remove_dir_all("/tmp/two_pass_test_aes_double").ok();
    Ok(())
}

#[tokio::test]
async fn test_chacha_double_pass() -> Result<(), Box<dyn std::error::Error>> {
    let master_key = [4u8; 32];
    let test_data = b"ChaCha double-pass encryption test";

    std::fs::create_dir_all("/tmp/two_pass_test_chacha_double").ok();

    // Encrypt: ChaCha with first key, then ChaCha with second key
    let ciphertext = Cipher::chachapoly()
        .with_key(
            Key::size(256.bits())
                .with_store(
                    FileKeyStore::at("/tmp/two_pass_test_chacha_double")
                        .with_master_key(master_key),
                )
                .with_namespace("test")
                .version(1),
        )
        .with_data(test_data)
        .second_pass(
            Cipher::chachapoly().with_key(
                Key::size(256.bits())
                    .with_store(
                        FileKeyStore::at("/tmp/two_pass_test_chacha_double")
                            .with_master_key(master_key),
                    )
                    .with_namespace("test")
                    .version(2),
            ),
        )
        .encrypt()
        .await?;

    // Decrypt: ChaCha with second key first, then ChaCha with first key
    let plaintext = Cipher::chachapoly()
        .with_key(
            Key::size(256.bits())
                .with_store(
                    FileKeyStore::at("/tmp/two_pass_test_chacha_double")
                        .with_master_key(master_key),
                )
                .with_namespace("test")
                .version(2),
        )
        .with_ciphertext(ciphertext.to_bytes())
        .second_pass(
            Cipher::chachapoly().with_key(
                Key::size(256.bits())
                    .with_store(
                        FileKeyStore::at("/tmp/two_pass_test_chacha_double")
                            .with_master_key(master_key),
                    )
                    .with_namespace("test")
                    .version(1),
            ),
        )
        .decrypt()
        .await?;

    assert_eq!(plaintext, test_data);

    std::fs::remove_dir_all("/tmp/two_pass_test_chacha_double").ok();
    Ok(())
}

#[tokio::test]
async fn test_two_pass_with_text() -> Result<(), Box<dyn std::error::Error>> {
    let master_key = [5u8; 32];
    let test_text = "Two-pass encryption with text input! 🔐";

    std::fs::create_dir_all("/tmp/two_pass_test_text").ok();

    // Encrypt with text input
    let ciphertext = Cipher::aes()
        .with_key(
            Key::size(256.bits())
                .with_store(FileKeyStore::at("/tmp/two_pass_test_text").with_master_key(master_key))
                .with_namespace("test")
                .version(1),
        )
        .with_text(test_text)
        .second_pass(
            Cipher::chachapoly().with_key(
                Key::size(256.bits())
                    .with_store(
                        FileKeyStore::at("/tmp/two_pass_test_text").with_master_key(master_key),
                    )
                    .with_namespace("test")
                    .version(2),
            ),
        )
        .encrypt()
        .await?;

    // Decrypt and convert back to text
    let plaintext = Cipher::chachapoly()
        .with_key(
            Key::size(256.bits())
                .with_store(FileKeyStore::at("/tmp/two_pass_test_text").with_master_key(master_key))
                .with_namespace("test")
                .version(2),
        )
        .with_ciphertext(ciphertext.to_bytes())
        .second_pass(
            Cipher::aes().with_key(
                Key::size(256.bits())
                    .with_store(
                        FileKeyStore::at("/tmp/two_pass_test_text").with_master_key(master_key),
                    )
                    .with_namespace("test")
                    .version(1),
            ),
        )
        .decrypt()
        .await?;

    let decrypted_text = String::from_utf8(plaintext)?;
    assert_eq!(decrypted_text, test_text);

    std::fs::remove_dir_all("/tmp/two_pass_test_text").ok();
    Ok(())
}

#[tokio::test]
async fn test_two_pass_with_encoding() -> Result<(), Box<dyn std::error::Error>> {
    let master_key = [6u8; 32];
    let test_data = b"Two-pass with base64 encoding";

    std::fs::create_dir_all("/tmp/two_pass_test_encoding").ok();

    // Encrypt and get base64
    let base64_ciphertext = Cipher::aes()
        .with_key(
            Key::size(256.bits())
                .with_store(
                    FileKeyStore::at("/tmp/two_pass_test_encoding").with_master_key(master_key),
                )
                .with_namespace("test")
                .version(1),
        )
        .with_data(test_data)
        .second_pass(
            Cipher::chachapoly().with_key(
                Key::size(256.bits())
                    .with_store(
                        FileKeyStore::at("/tmp/two_pass_test_encoding").with_master_key(master_key),
                    )
                    .with_namespace("test")
                    .version(2),
            ),
        )
        .encrypt()
        .await?
        .to_base64();

    // Decrypt from base64
    let plaintext = Cipher::chachapoly()
        .with_key(
            Key::size(256.bits())
                .with_store(
                    FileKeyStore::at("/tmp/two_pass_test_encoding").with_master_key(master_key),
                )
                .with_namespace("test")
                .version(2),
        )
        .with_ciphertext_base64(&base64_ciphertext)?
        .second_pass(
            Cipher::aes().with_key(
                Key::size(256.bits())
                    .with_store(
                        FileKeyStore::at("/tmp/two_pass_test_encoding").with_master_key(master_key),
                    )
                    .with_namespace("test")
                    .version(1),
            ),
        )
        .decrypt()
        .await?;

    assert_eq!(plaintext, test_data);

    std::fs::remove_dir_all("/tmp/two_pass_test_encoding").ok();
    Ok(())
}

#[tokio::test]
async fn test_two_pass_with_files() -> Result<(), Box<dyn std::error::Error>> {
    let master_key = [7u8; 32];
    let test_dir = "/tmp/two_pass_test_files";
    let input_file = format!("{}/input.txt", test_dir);
    let output_file = format!("{}/encrypted.bin", test_dir);
    let test_data = b"Two-pass encryption with file operations";

    std::fs::create_dir_all(test_dir)?;
    std::fs::write(&input_file, test_data)?;

    // Encrypt from file and save to file
    let ciphertext = Cipher::aes()
        .with_key(
            Key::size(256.bits())
                .with_store(FileKeyStore::at(test_dir).with_master_key(master_key))
                .with_namespace("test")
                .version(1),
        )
        .with_file(&input_file)
        .await?
        .second_pass(
            Cipher::chachapoly().with_key(
                Key::size(256.bits())
                    .with_store(FileKeyStore::at(test_dir).with_master_key(master_key))
                    .with_namespace("test")
                    .version(2),
            ),
        )
        .encrypt()
        .await?;

    ciphertext.to_file(&output_file).await?;

    // Decrypt from file
    let plaintext = Cipher::chachapoly()
        .with_key(
            Key::size(256.bits())
                .with_store(FileKeyStore::at(test_dir).with_master_key(master_key))
                .with_namespace("test")
                .version(2),
        )
        .with_ciphertext_file(&output_file)
        .await?
        .second_pass(
            Cipher::aes().with_key(
                Key::size(256.bits())
                    .with_store(FileKeyStore::at(test_dir).with_master_key(master_key))
                    .with_namespace("test")
                    .version(1),
            ),
        )
        .decrypt()
        .await?;

    assert_eq!(plaintext, test_data);

    std::fs::remove_dir_all(test_dir).ok();
    Ok(())
}

#[tokio::test]
async fn test_two_pass_large_data() -> Result<(), Box<dyn std::error::Error>> {
    let master_key = [8u8; 32];
    let large_data: Vec<u8> = (0..5000).map(|i| (i % 256) as u8).collect();

    std::fs::create_dir_all("/tmp/two_pass_test_large").ok();

    // Encrypt large data with two passes
    let ciphertext = Cipher::aes()
        .with_key(
            Key::size(256.bits())
                .with_store(
                    FileKeyStore::at("/tmp/two_pass_test_large").with_master_key(master_key),
                )
                .with_namespace("test")
                .version(1),
        )
        .with_data(large_data.clone())
        .second_pass(
            Cipher::chachapoly().with_key(
                Key::size(256.bits())
                    .with_store(
                        FileKeyStore::at("/tmp/two_pass_test_large").with_master_key(master_key),
                    )
                    .with_namespace("test")
                    .version(2),
            ),
        )
        .encrypt()
        .await?;

    // Decrypt
    let plaintext = Cipher::chachapoly()
        .with_key(
            Key::size(256.bits())
                .with_store(
                    FileKeyStore::at("/tmp/two_pass_test_large").with_master_key(master_key),
                )
                .with_namespace("test")
                .version(2),
        )
        .with_ciphertext(ciphertext.to_bytes())
        .second_pass(
            Cipher::aes().with_key(
                Key::size(256.bits())
                    .with_store(
                        FileKeyStore::at("/tmp/two_pass_test_large").with_master_key(master_key),
                    )
                    .with_namespace("test")
                    .version(1),
            ),
        )
        .decrypt()
        .await?;

    assert_eq!(plaintext, large_data);
    assert_eq!(plaintext.len(), 5000);

    std::fs::remove_dir_all("/tmp/two_pass_test_large").ok();
    Ok(())
}

#[tokio::test]
async fn test_two_pass_empty_data() -> Result<(), Box<dyn std::error::Error>> {
    let master_key = [9u8; 32];
    let empty_data: Vec<u8> = Vec::new();

    std::fs::create_dir_all("/tmp/two_pass_test_empty").ok();

    // Encrypt empty data with two passes
    let ciphertext = Cipher::aes()
        .with_key(
            Key::size(256.bits())
                .with_store(
                    FileKeyStore::at("/tmp/two_pass_test_empty").with_master_key(master_key),
                )
                .with_namespace("test")
                .version(1),
        )
        .with_data(empty_data.clone())
        .second_pass(
            Cipher::chachapoly().with_key(
                Key::size(256.bits())
                    .with_store(
                        FileKeyStore::at("/tmp/two_pass_test_empty").with_master_key(master_key),
                    )
                    .with_namespace("test")
                    .version(2),
            ),
        )
        .encrypt()
        .await?;

    // Should still produce ciphertext
    assert!(!ciphertext.to_bytes().is_empty());

    // Decrypt
    let plaintext = Cipher::chachapoly()
        .with_key(
            Key::size(256.bits())
                .with_store(
                    FileKeyStore::at("/tmp/two_pass_test_empty").with_master_key(master_key),
                )
                .with_namespace("test")
                .version(2),
        )
        .with_ciphertext(ciphertext.to_bytes())
        .second_pass(
            Cipher::aes().with_key(
                Key::size(256.bits())
                    .with_store(
                        FileKeyStore::at("/tmp/two_pass_test_empty").with_master_key(master_key),
                    )
                    .with_namespace("test")
                    .version(1),
            ),
        )
        .decrypt()
        .await?;

    assert_eq!(plaintext, empty_data);
    assert!(plaintext.is_empty());

    std::fs::remove_dir_all("/tmp/two_pass_test_empty").ok();
    Ok(())
}

#[tokio::test]
async fn test_two_pass_wrong_order_fails() {
    let master_key = [10u8; 32];
    let test_data = b"Wrong order decryption test";

    std::fs::create_dir_all("/tmp/two_pass_test_wrong_order").ok();

    // Encrypt: AES first, then ChaCha
    let ciphertext = Cipher::aes()
        .with_key(
            Key::size(256.bits())
                .with_store(
                    FileKeyStore::at("/tmp/two_pass_test_wrong_order").with_master_key(master_key),
                )
                .with_namespace("test")
                .version(1),
        )
        .with_data(test_data)
        .second_pass(
            Cipher::chachapoly().with_key(
                Key::size(256.bits())
                    .with_store(
                        FileKeyStore::at("/tmp/two_pass_test_wrong_order")
                            .with_master_key(master_key),
                    )
                    .with_namespace("test")
                    .version(2),
            ),
        )
        .encrypt()
        .await
        .unwrap();

    // Try to decrypt in wrong order: AES first instead of ChaCha first
    let result = Cipher::aes()
        .with_key(
            Key::size(256.bits())
                .with_store(
                    FileKeyStore::at("/tmp/two_pass_test_wrong_order").with_master_key(master_key),
                )
                .with_namespace("test")
                .version(1),
        )
        .with_ciphertext(ciphertext.to_bytes())
        .second_pass(
            Cipher::chachapoly().with_key(
                Key::size(256.bits())
                    .with_store(
                        FileKeyStore::at("/tmp/two_pass_test_wrong_order")
                            .with_master_key(master_key),
                    )
                    .with_namespace("test")
                    .version(2),
            ),
        )
        .decrypt()
        .await;

    // This should fail because we're decrypting in the wrong order
    assert!(result.is_err());

    std::fs::remove_dir_all("/tmp/two_pass_test_wrong_order").ok();
}

#[tokio::test]
async fn test_two_pass_different_namespaces() -> Result<(), Box<dyn std::error::Error>> {
    let master_key = [11u8; 32];
    let test_data = b"Different namespaces test";

    std::fs::create_dir_all("/tmp/two_pass_test_namespaces").ok();

    // Encrypt with different namespaces for each pass
    let ciphertext = Cipher::aes()
        .with_key(
            Key::size(256.bits())
                .with_store(
                    FileKeyStore::at("/tmp/two_pass_test_namespaces").with_master_key(master_key),
                )
                .with_namespace("first-pass")
                .version(1),
        )
        .with_data(test_data)
        .second_pass(
            Cipher::chachapoly().with_key(
                Key::size(256.bits())
                    .with_store(
                        FileKeyStore::at("/tmp/two_pass_test_namespaces")
                            .with_master_key(master_key),
                    )
                    .with_namespace("second-pass")
                    .version(1),
            ),
        )
        .encrypt()
        .await?;

    // Decrypt with matching namespaces
    let plaintext = Cipher::chachapoly()
        .with_key(
            Key::size(256.bits())
                .with_store(
                    FileKeyStore::at("/tmp/two_pass_test_namespaces").with_master_key(master_key),
                )
                .with_namespace("second-pass")
                .version(1),
        )
        .with_ciphertext(ciphertext.to_bytes())
        .second_pass(
            Cipher::aes().with_key(
                Key::size(256.bits())
                    .with_store(
                        FileKeyStore::at("/tmp/two_pass_test_namespaces")
                            .with_master_key(master_key),
                    )
                    .with_namespace("first-pass")
                    .version(1),
            ),
        )
        .decrypt()
        .await?;

    assert_eq!(plaintext, test_data);

    std::fs::remove_dir_all("/tmp/two_pass_test_namespaces").ok();
    Ok(())
}
