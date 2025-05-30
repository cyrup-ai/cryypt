//! Unit tests for compression integration with cipher functionality

use cryypt::prelude::*;
use std::fs;

#[tokio::test]
async fn test_aes_with_zstd_compression() -> Result<(), Box<dyn std::error::Error>> {
    let master_key = [1u8; 32];
    let test_data = "This is test data that should compress well. ".repeat(20); // Repetitive data compresses well

    std::fs::create_dir_all("/tmp/comp_test_aes_zstd").ok();

    // Encrypt with compression
    let compressed_ciphertext = Cipher::aes()
        .with_key(
            Key::size(256.bits())
                .with_store(FileKeyStore::at("/tmp/comp_test_aes_zstd").with_master_key(master_key))
                .with_namespace("test")
                .version(1),
        )
        .with_compression(Compress::zstd())
        .with_text(&test_data)
        .encrypt()
        .await?;

    // Encrypt without compression for comparison
    let normal_ciphertext = Cipher::aes()
        .with_key(
            Key::size(256.bits())
                .with_store(FileKeyStore::at("/tmp/comp_test_aes_zstd").with_master_key(master_key))
                .with_namespace("test")
                .version(2),
        )
        .with_text(&test_data)
        .encrypt()
        .await?;

    // Compressed ciphertext should be smaller
    assert!(compressed_ciphertext.len() < normal_ciphertext.len());

    // Decrypt with compression
    let decrypted_data = Cipher::aes()
        .with_key(
            Key::size(256.bits())
                .with_store(FileKeyStore::at("/tmp/comp_test_aes_zstd").with_master_key(master_key))
                .with_namespace("test")
                .version(1),
        )
        .with_compression(Compress::zstd())
        .with_ciphertext(compressed_ciphertext.to_bytes())
        .decrypt()
        .await?;

    let decrypted_text = String::from_utf8(decrypted_data)?;
    assert_eq!(decrypted_text, test_data);

    std::fs::remove_dir_all("/tmp/comp_test_aes_zstd").ok();
    Ok(())
}

#[tokio::test]
async fn test_chacha_with_zstd_compression() -> Result<(), Box<dyn std::error::Error>> {
    let master_key = [2u8; 32];
    let test_data = "ChaCha compression test data. ".repeat(50);

    std::fs::create_dir_all("/tmp/comp_test_chacha_zstd").ok();

    // Encrypt with compression
    let compressed_ciphertext = Cipher::chachapoly()
        .with_key(
            Key::size(256.bits())
                .with_store(
                    FileKeyStore::at("/tmp/comp_test_chacha_zstd").with_master_key(master_key),
                )
                .with_namespace("test")
                .version(1),
        )
        .with_compression(Compress::zstd())
        .with_text(&test_data)
        .encrypt()
        .await?;

    // Decrypt with compression
    let decrypted_data = Cipher::chachapoly()
        .with_key(
            Key::size(256.bits())
                .with_store(
                    FileKeyStore::at("/tmp/comp_test_chacha_zstd").with_master_key(master_key),
                )
                .with_namespace("test")
                .version(1),
        )
        .with_compression(Compress::zstd())
        .with_ciphertext(compressed_ciphertext.to_bytes())
        .decrypt()
        .await?;

    let decrypted_text = String::from_utf8(decrypted_data)?;
    assert_eq!(decrypted_text, test_data);

    std::fs::remove_dir_all("/tmp/comp_test_chacha_zstd").ok();
    Ok(())
}

#[tokio::test]
async fn test_aes_with_bzip2_compression() -> Result<(), Box<dyn std::error::Error>> {
    let master_key = [3u8; 32];
    let test_data = "BZip2 compression test data. ".repeat(30);

    std::fs::create_dir_all("/tmp/comp_test_aes_bzip2").ok();

    // Encrypt with bzip2 compression
    let compressed_ciphertext = Cipher::aes()
        .with_key(
            Key::size(256.bits())
                .with_store(
                    FileKeyStore::at("/tmp/comp_test_aes_bzip2").with_master_key(master_key),
                )
                .with_namespace("test")
                .version(1),
        )
        .with_compression(Compress::bzip2().balanced_compression())
        .with_text(&test_data)
        .encrypt()
        .await?;

    // Decrypt with bzip2 compression
    let decrypted_data = Cipher::aes()
        .with_key(
            Key::size(256.bits())
                .with_store(
                    FileKeyStore::at("/tmp/comp_test_aes_bzip2").with_master_key(master_key),
                )
                .with_namespace("test")
                .version(1),
        )
        .with_compression(Compress::bzip2().balanced_compression())
        .with_ciphertext(compressed_ciphertext.to_bytes())
        .decrypt()
        .await?;

    let decrypted_text = String::from_utf8(decrypted_data)?;
    assert_eq!(decrypted_text, test_data);

    std::fs::remove_dir_all("/tmp/comp_test_aes_bzip2").ok();
    Ok(())
}

#[tokio::test]
async fn test_compression_with_encoding() -> Result<(), Box<dyn std::error::Error>> {
    let master_key = [4u8; 32];
    let test_data = "Compression + encoding test. ".repeat(25);

    std::fs::create_dir_all("/tmp/comp_test_encoding").ok();

    // Encrypt with compression and get base64
    let base64_result = Cipher::aes()
        .with_key(
            Key::size(256.bits())
                .with_store(FileKeyStore::at("/tmp/comp_test_encoding").with_master_key(master_key))
                .with_namespace("test")
                .version(1),
        )
        .with_compression(Compress::zstd())
        .with_text(&test_data)
        .encrypt()
        .await?
        .to_base64();

    // Decrypt from base64 with compression
    let decrypted_data = Cipher::aes()
        .with_key(
            Key::size(256.bits())
                .with_store(FileKeyStore::at("/tmp/comp_test_encoding").with_master_key(master_key))
                .with_namespace("test")
                .version(1),
        )
        .with_compression(Compress::zstd())
        .with_ciphertext_base64(&base64_result)?
        .decrypt()
        .await?;

    let decrypted_text = String::from_utf8(decrypted_data)?;
    assert_eq!(decrypted_text, test_data);

    std::fs::remove_dir_all("/tmp/comp_test_encoding").ok();
    Ok(())
}

#[tokio::test]
async fn test_compression_with_files() -> Result<(), Box<dyn std::error::Error>> {
    let master_key = [5u8; 32];
    let test_dir = "/tmp/comp_test_files";
    let input_file = format!("{}/input.txt", test_dir);
    let encrypted_file = format!("{}/encrypted.bin", test_dir);
    let test_data = "File compression test data. ".repeat(40);

    std::fs::create_dir_all(test_dir)?;
    std::fs::write(&input_file, &test_data)?;

    // Encrypt file with compression and save to file
    let compressed_result = Cipher::aes()
        .with_key(
            Key::size(256.bits())
                .with_store(FileKeyStore::at(test_dir).with_master_key(master_key))
                .with_namespace("test")
                .version(1),
        )
        .with_compression(Compress::zstd())
        .with_file(&input_file)
        .await?
        .encrypt()
        .await?;

    compressed_result.to_file(&encrypted_file).await?;

    // Decrypt from file with compression
    let decrypted_data = Cipher::aes()
        .with_key(
            Key::size(256.bits())
                .with_store(FileKeyStore::at(test_dir).with_master_key(master_key))
                .with_namespace("test")
                .version(1),
        )
        .with_compression(Compress::zstd())
        .with_ciphertext_file(&encrypted_file)
        .await?
        .decrypt()
        .await?;

    let decrypted_text = String::from_utf8(decrypted_data)?;
    assert_eq!(decrypted_text, test_data);

    std::fs::remove_dir_all(test_dir).ok();
    Ok(())
}

#[tokio::test]
async fn test_compression_binary_data() -> Result<(), Box<dyn std::error::Error>> {
    let master_key = [6u8; 32];
    // Create repetitive binary data that compresses well
    let mut binary_data = Vec::new();
    for _ in 0..1000 {
        binary_data.extend_from_slice(&[0x00, 0x01, 0x02, 0x03]);
    }

    std::fs::create_dir_all("/tmp/comp_test_binary").ok();

    // Encrypt with compression
    let compressed_ciphertext = Cipher::aes()
        .with_key(
            Key::size(256.bits())
                .with_store(FileKeyStore::at("/tmp/comp_test_binary").with_master_key(master_key))
                .with_namespace("test")
                .version(1),
        )
        .with_compression(Compress::zstd())
        .with_data(binary_data.clone())
        .encrypt()
        .await?;

    // Encrypt without compression for size comparison
    let normal_ciphertext = Cipher::aes()
        .with_key(
            Key::size(256.bits())
                .with_store(FileKeyStore::at("/tmp/comp_test_binary").with_master_key(master_key))
                .with_namespace("test")
                .version(2),
        )
        .with_data(binary_data.clone())
        .encrypt()
        .await?;

    // Compressed should be significantly smaller
    assert!(compressed_ciphertext.len() < normal_ciphertext.len());

    // Decrypt with compression
    let decrypted_data = Cipher::aes()
        .with_key(
            Key::size(256.bits())
                .with_store(FileKeyStore::at("/tmp/comp_test_binary").with_master_key(master_key))
                .with_namespace("test")
                .version(1),
        )
        .with_compression(Compress::zstd())
        .with_ciphertext(compressed_ciphertext.to_bytes())
        .decrypt()
        .await?;

    assert_eq!(decrypted_data, binary_data);

    std::fs::remove_dir_all("/tmp/comp_test_binary").ok();
    Ok(())
}

#[tokio::test]
async fn test_compression_empty_data() -> Result<(), Box<dyn std::error::Error>> {
    let master_key = [7u8; 32];
    let empty_data: Vec<u8> = Vec::new();

    std::fs::create_dir_all("/tmp/comp_test_empty").ok();

    // Encrypt empty data with compression
    let compressed_ciphertext = Cipher::aes()
        .with_key(
            Key::size(256.bits())
                .with_store(FileKeyStore::at("/tmp/comp_test_empty").with_master_key(master_key))
                .with_namespace("test")
                .version(1),
        )
        .with_compression(Compress::zstd())
        .with_data(empty_data.clone())
        .encrypt()
        .await?;

    // Should still produce ciphertext (nonce + auth tag + compressed empty data)
    assert!(!compressed_ciphertext.to_bytes().is_empty());

    // Decrypt with compression
    let decrypted_data = Cipher::aes()
        .with_key(
            Key::size(256.bits())
                .with_store(FileKeyStore::at("/tmp/comp_test_empty").with_master_key(master_key))
                .with_namespace("test")
                .version(1),
        )
        .with_compression(Compress::zstd())
        .with_ciphertext(compressed_ciphertext.to_bytes())
        .decrypt()
        .await?;

    assert_eq!(decrypted_data, empty_data);
    assert!(decrypted_data.is_empty());

    std::fs::remove_dir_all("/tmp/comp_test_empty").ok();
    Ok(())
}

#[tokio::test]
async fn test_compression_large_data() -> Result<(), Box<dyn std::error::Error>> {
    let master_key = [8u8; 32];
    // Create large repetitive data
    let large_data = "Large repetitive data for compression testing. ".repeat(500);

    std::fs::create_dir_all("/tmp/comp_test_large").ok();

    // Encrypt with compression
    let compressed_ciphertext = Cipher::aes()
        .with_key(
            Key::size(256.bits())
                .with_store(FileKeyStore::at("/tmp/comp_test_large").with_master_key(master_key))
                .with_namespace("test")
                .version(1),
        )
        .with_compression(Compress::zstd())
        .with_text(&large_data)
        .encrypt()
        .await?;

    // Decrypt with compression
    let decrypted_data = Cipher::aes()
        .with_key(
            Key::size(256.bits())
                .with_store(FileKeyStore::at("/tmp/comp_test_large").with_master_key(master_key))
                .with_namespace("test")
                .version(1),
        )
        .with_compression(Compress::zstd())
        .with_ciphertext(compressed_ciphertext.to_bytes())
        .decrypt()
        .await?;

    let decrypted_text = String::from_utf8(decrypted_data)?;
    assert_eq!(decrypted_text, large_data);
    assert_eq!(decrypted_text.len(), large_data.len());

    std::fs::remove_dir_all("/tmp/comp_test_large").ok();
    Ok(())
}

#[tokio::test]
async fn test_compression_mismatch_error() {
    let master_key = [9u8; 32];
    let test_data = "Compression mismatch test data.";

    std::fs::create_dir_all("/tmp/comp_test_mismatch").ok();

    // Encrypt with compression
    let compressed_ciphertext = Cipher::aes()
        .with_key(
            Key::size(256.bits())
                .with_store(FileKeyStore::at("/tmp/comp_test_mismatch").with_master_key(master_key))
                .with_namespace("test")
                .version(1),
        )
        .with_compression(Compress::zstd())
        .with_text(test_data)
        .encrypt()
        .await
        .unwrap();

    // Try to decrypt without compression - should fail or give wrong result
    let result = Cipher::aes()
        .with_key(
            Key::size(256.bits())
                .with_store(FileKeyStore::at("/tmp/comp_test_mismatch").with_master_key(master_key))
                .with_namespace("test")
                .version(1),
        )
        .with_ciphertext(compressed_ciphertext.to_bytes())
        .decrypt()
        .await;

    // This should succeed (decryption works) but the result won't be the original text
    // because it's the compressed data, not the original text
    if let Ok(decrypted_compressed_data) = result {
        let attempted_text = String::from_utf8_lossy(&decrypted_compressed_data);
        assert_ne!(attempted_text, test_data);
    }

    std::fs::remove_dir_all("/tmp/comp_test_mismatch").ok();
}

#[tokio::test]
async fn test_multiple_compression_algorithms() -> Result<(), Box<dyn std::error::Error>> {
    let master_key = [10u8; 32];
    let test_data = "Multi-algorithm compression test. ".repeat(20);

    std::fs::create_dir_all("/tmp/comp_test_multi").ok();

    // Test zstd
    let zstd_ciphertext = Cipher::aes()
        .with_key(
            Key::size(256.bits())
                .with_store(FileKeyStore::at("/tmp/comp_test_multi").with_master_key(master_key))
                .with_namespace("test")
                .version(1),
        )
        .with_compression(Compress::zstd())
        .with_text(&test_data)
        .encrypt()
        .await?;

    // Test bzip2
    let bzip2_ciphertext = Cipher::aes()
        .with_key(
            Key::size(256.bits())
                .with_store(FileKeyStore::at("/tmp/comp_test_multi").with_master_key(master_key))
                .with_namespace("test")
                .version(2),
        )
        .with_compression(Compress::bzip2())
        .with_text(&test_data)
        .encrypt()
        .await?;

    // Verify they produce different ciphertexts
    assert_ne!(zstd_ciphertext.to_bytes(), bzip2_ciphertext.to_bytes());

    // Decrypt both
    let zstd_decrypted = Cipher::aes()
        .with_key(
            Key::size(256.bits())
                .with_store(FileKeyStore::at("/tmp/comp_test_multi").with_master_key(master_key))
                .with_namespace("test")
                .version(1),
        )
        .with_compression(Compress::zstd())
        .with_ciphertext(zstd_ciphertext.to_bytes())
        .decrypt()
        .await?;

    let bzip2_decrypted = Cipher::aes()
        .with_key(
            Key::size(256.bits())
                .with_store(FileKeyStore::at("/tmp/comp_test_multi").with_master_key(master_key))
                .with_namespace("test")
                .version(2),
        )
        .with_compression(Compress::bzip2())
        .with_ciphertext(bzip2_ciphertext.to_bytes())
        .decrypt()
        .await?;

    // Both should decrypt to the same original data
    let zstd_text = String::from_utf8(zstd_decrypted)?;
    let bzip2_text = String::from_utf8(bzip2_decrypted)?;

    assert_eq!(zstd_text, test_data);
    assert_eq!(bzip2_text, test_data);
    assert_eq!(zstd_text, bzip2_text);

    std::fs::remove_dir_all("/tmp/comp_test_multi").ok();
    Ok(())
}
