//! Test the exact syntax from README.md

use cyrup_crypt::{Cipher, Key, Bits};
use cyrup_crypt::key::stores::FileKeyStore;
use cyrup_crypt::cipher::api::{KeyBuilder, DataBuilder, EncryptBuilder};
use cyrup_crypt::cipher::api::builder_traits::{CiphertextBuilder, DecryptBuilder};
use cyrup_crypt::compression::{Compress, DataBuilder as CompressionDataBuilder, CompressExecutor, DecompressExecutor};

#[tokio::test]
async fn test_aes_basic_syntax() {
    // Test the basic AES encryption syntax from README
    let ciphertext = Cipher::aes()
        .with_key(Key::size(256.bits()))
        .with_data(b"Hello, World!")
        .encrypt()
        .await
        .expect("Encryption should work");

    assert!(!ciphertext.is_empty());
}

#[tokio::test] 
async fn test_chacha_basic_syntax() {
    // Test the basic ChaCha syntax from README
    let ciphertext = Cipher::chachapoly()
        .with_key(Key::size(256.bits()))
        .with_data(b"Secret message")
        .encrypt()
        .await
        .expect("ChaCha encryption should work");

    assert!(!ciphertext.is_empty());
}

#[tokio::test]
async fn test_aes_with_store_basic() {
    let master_key = [0u8; 32];
    
    // Test AES with file store using the exact syntax from README.md
    let ciphertext = Cipher::aes()
        .with_key(Key::size(256.bits())
            .with_store(FileKeyStore::at("/tmp/test_keys").with_master_key(master_key))
            .with_namespace("my-app")
            .version(1))
        .with_data(b"Hello, World!")
        .encrypt()
        .await
        .expect("Encryption should work");

    assert!(!ciphertext.is_empty());
}

#[tokio::test]
async fn test_aes_encrypt_decrypt_round_trip() {
    let master_key = [0u8; 32];
    
    // Test the exact encryption/decryption syntax from README.md
    let original_data = b"Hello, World!";
    
    // Encrypt
    let ciphertext = Cipher::aes()
        .with_key(Key::size(256.bits())
            .with_store(FileKeyStore::at("/tmp/test_keys_decrypt").with_master_key(master_key))
            .with_namespace("my-app")
            .version(1))
        .with_data(original_data)
        .encrypt()
        .await
        .expect("Encryption should work");

    assert!(!ciphertext.is_empty());
    
    // Decrypt using the exact syntax from README.md
    let plaintext = Cipher::aes()
        .with_key(Key::size(256.bits())
            .with_store(FileKeyStore::at("/tmp/test_keys_decrypt").with_master_key(master_key))
            .with_namespace("my-app")
            .version(1))
        .with_ciphertext(ciphertext)
        .decrypt()
        .await
        .expect("Decryption should work");

    assert_eq!(plaintext, original_data);
}

#[tokio::test]
async fn test_zstd_compression() {
    let original_text = b"Large text that compresses well and should demonstrate good compression ratios with zstd algorithm";
    
    // Test compression
    let compressed = Compress::zstd()
        .with_data(original_text)
        .compress()
        .await
        .expect("Compression should work");
    
    assert!(!compressed.is_empty());
    assert!(compressed.len() < original_text.len()); // Should be smaller
    
    // Test decompression
    let decompressed = Compress::zstd()
        .with_data(compressed)
        .decompress()
        .await
        .expect("Decompression should work");
    
    assert_eq!(decompressed, original_text);
}