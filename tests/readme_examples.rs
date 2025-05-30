//! Integration tests for all README examples
//! These tests verify that every example in README.md actually compiles and works

use cryypt::prelude::*;

// Import traits needed for builder methods
use cryypt::cipher::api::builder_traits::{
    CiphertextBuilder, DataBuilder as CipherDataBuilder, DecryptBuilder, DecryptSecondPass,
    EncryptBuilder, EncryptSecondPass, KeyBuilder, WithCompression,
};
use cryypt::compression::api::{
    CompressExecutor, DataBuilder as CompressDataBuilder, DecompressExecutor,
};
use cryypt::hashing::api::{
    DataBuilder as HashDataBuilder, HashExecutor, PassesBuilder, SaltBuilder,
};

#[tokio::test]
async fn test_aes_gcm_encryption() -> Result<(), Box<dyn std::error::Error>> {
    let master_key = [1u8; 32]; // Test key

    // Simple encryption with key
    let ciphertext = Cipher::aes()
        .with_key(
            Key::size(256u32.bits())
                .with_store(FileKeyStore::at("/tmp/test_keys").with_master_key(master_key))
                .with_namespace("my-app")
                .version(1),
        )
        .with_data(b"Hello, World!")
        .encrypt()
        .await?;

    // Decrypt
    let plaintext = Cipher::aes()
        .with_key(
            Key::size(256u32.bits())
                .with_store(FileKeyStore::at("/tmp/test_keys").with_master_key(master_key))
                .with_namespace("my-app")
                .version(1),
        )
        .with_ciphertext(ciphertext)
        .decrypt()
        .await?;

    assert_eq!(plaintext, b"Hello, World!");
    Ok(())
}

#[tokio::test]
async fn test_chacha20_poly1305_encryption() -> Result<(), Box<dyn std::error::Error>> {
    let master_key = [3u8; 32]; // Test key

    // Encrypt with ChaCha20-Poly1305
    let ciphertext = Cipher::chachapoly()
        .with_key(
            Key::size(256u32.bits())
                .with_store(FileKeyStore::at("/tmp/test_chacha_keys").with_master_key(master_key))
                .with_namespace("secure-app")
                .version(1),
        )
        .with_data(b"Secret message")
        .encrypt()
        .await?;

    // Decrypt
    let plaintext = Cipher::chachapoly()
        .with_key(
            Key::size(256u32.bits())
                .with_store(FileKeyStore::at("/tmp/test_chacha_keys").with_master_key(master_key))
                .with_namespace("secure-app")
                .version(1),
        )
        .with_ciphertext(ciphertext)
        .decrypt()
        .await?;

    assert_eq!(plaintext, b"Secret message");
    Ok(())
}

#[tokio::test]
async fn test_two_pass_encryption() -> Result<(), Box<dyn std::error::Error>> {
    let master_key = [2u8; 32]; // Test key

    // Double encryption: AES-GCM followed by ChaCha20-Poly1305
    let ciphertext = Cipher::aes()
        .with_key(
            Key::size(256u32.bits())
                .with_store(FileKeyStore::at("/tmp/test_keys_2pass").with_master_key(master_key))
                .with_namespace("app")
                .version(1),
        )
        .with_data(b"Top secret")
        .second_pass(
            Cipher::chachapoly().with_key(
                Key::size(256u32.bits())
                    .with_store(
                        FileKeyStore::at("/tmp/test_keys_2pass").with_master_key(master_key),
                    )
                    .with_namespace("app")
                    .version(2),
            ),
        )
        .encrypt()
        .await?;

    // Decrypt in reverse order (ChaCha first, then AES)
    let plaintext = Cipher::chachapoly()
        .with_key(
            Key::size(256u32.bits())
                .with_store(FileKeyStore::at("/tmp/test_keys_2pass").with_master_key(master_key))
                .with_namespace("app")
                .version(2),
        )
        .with_ciphertext(ciphertext)
        .second_pass(
            Cipher::aes().with_key(
                Key::size(256u32.bits())
                    .with_store(
                        FileKeyStore::at("/tmp/test_keys_2pass").with_master_key(master_key),
                    )
                    .with_namespace("app")
                    .version(1),
            ),
        )
        .decrypt()
        .await?;

    assert_eq!(plaintext, b"Top secret");
    Ok(())
}

#[tokio::test]
async fn test_sha256_hashing() -> Result<(), Box<dyn std::error::Error>> {
    // Simple hash
    let hash = Hash::sha256().with_data(b"Hello, World!").hash().await?;

    assert_eq!(hash.len(), 32); // SHA-256 produces 32 bytes

    // Hash with salt
    let hash_with_salt = Hash::sha256()
        .with_data(b"password")
        .with_salt(b"random_salt")
        .hash()
        .await?;

    assert_eq!(hash_with_salt.len(), 32);
    assert_ne!(hash, hash_with_salt); // Should be different

    // Hash with multiple passes (key stretching)
    let stretched_hash = Hash::sha256()
        .with_data(b"password")
        .with_salt(b"random_salt")
        .with_passes(1_000) // Use smaller number for tests
        .hash()
        .await?;

    assert_eq!(stretched_hash.len(), 32);
    assert_ne!(hash_with_salt, stretched_hash); // Should be different due to stretching
    Ok(())
}

#[tokio::test]
async fn test_blake2b_hashing() -> Result<(), Box<dyn std::error::Error>> {
    // Blake2b with default 64-byte output
    let hash = Hash::blake2b().with_data(b"Hello, World!").hash().await?;

    assert_eq!(hash.len(), 64); // Blake2b default is 64 bytes

    // Blake2b with key (for MAC)
    let mac = Hash::blake2b()
        .with_data(b"message")
        .with_salt(b"secret_key") // salt acts as key in Blake2b
        .hash()
        .await?;

    assert_eq!(mac.len(), 64);
    assert_ne!(hash, mac); // Should be different
    Ok(())
}

#[tokio::test]
async fn test_sha3_hashing() -> Result<(), Box<dyn std::error::Error>> {
    // SHA3-256 (default)
    let hash = Hash::sha3().with_data(b"data").hash().await?;

    assert_eq!(hash.len(), 32); // SHA3-256 produces 32 bytes

    // SHA3 with salt and passes
    let stretched_hash = Hash::sha3()
        .with_data(b"password")
        .with_salt(b"salt")
        .with_passes(100) // Use smaller number for tests
        .hash()
        .await?;

    assert_eq!(stretched_hash.len(), 32);
    assert_ne!(hash, stretched_hash); // Should be different
    Ok(())
}

#[tokio::test]
async fn test_text_input_hashing() -> Result<(), Box<dyn std::error::Error>> {
    // Hash text directly
    let hash = Hash::sha256().with_text("Hello, World!").hash().await?;

    assert_eq!(hash.len(), 32);

    // Combine with other options
    let hash_with_salt = Hash::blake2b()
        .with_text("user@example.com")
        .with_salt(b"app_specific_salt")
        .hash()
        .await?;

    assert_eq!(hash_with_salt.len(), 64);
    Ok(())
}

#[tokio::test]
async fn test_integrated_key_generation() -> Result<(), Box<dyn std::error::Error>> {
    let master_key = [4u8; 32]; // Test key

    // Generate key and encrypt data in one beautiful chain
    let ciphertext = Cipher::aes()
        .with_key(
            Key::size(256u32.bits())
                .with_store(
                    FileKeyStore::at("/tmp/test_keys_integrated").with_master_key(master_key),
                )
                .with_namespace("production")
                .version(1),
        )
        .with_data(b"Secret data")
        .encrypt()
        .await?;

    // Later: decrypt (key automatically retrieved)
    let plaintext = Cipher::aes()
        .with_key(
            Key::size(256u32.bits())
                .with_store(
                    FileKeyStore::at("/tmp/test_keys_integrated").with_master_key(master_key),
                )
                .with_namespace("production")
                .version(1),
        )
        .with_ciphertext(ciphertext)
        .decrypt()
        .await?;

    assert_eq!(plaintext, b"Secret data");
    Ok(())
}

#[tokio::test]
#[cfg(feature = "aws")]
async fn test_aws_kms_integration() -> Result<(), Box<dyn std::error::Error>> {
    // Skip if AWS credentials not available
    if std::env::var("AWS_ACCESS_KEY_ID").is_err() {
        return Ok(()); // Skip test if no AWS creds
    }

    // Note: AwsKms implementation would need to be imported
    use cyrup_crypt::key::stores::{AwsKmsDataKeyStore, AwsSecretsManagerStore};

    // Encrypt with KMS-managed key (generates on first use)
    let ciphertext = Cipher::chachapoly()
        .with_key(
            Key::size(256u32.bits())
                .with_store(AwsKmsDataKeyStore::new(
                    "alias/production-cmk",
                    AwsSecretsManagerStore::new("prod/keys"),
                ))
                .with_namespace("api-service")
                .version(1),
        )
        .with_data(b"Customer PII")
        .encrypt()
        .await?;

    assert!(!ciphertext.is_empty());
    Ok(())
}

#[tokio::test]
async fn test_os_keychain_storage() -> Result<(), Box<dyn std::error::Error>> {
    // Encrypt user data (key generated/retrieved automatically)
    let encrypted = Cipher::aes()
        .with_key(
            Key::size(256u32.bits())
                .with_store(KeychainStore::for_app("MyTestApp"))
                .with_namespace("user-keys")
                .version(1),
        )
        .with_data(b"User secrets")
        .encrypt()
        .await?;

    assert!(!encrypted.is_empty());
    Ok(())
}

#[tokio::test]
async fn test_bzip2_compression() -> Result<(), Box<dyn std::error::Error>> {
    // Simple compression
    let compressed = Compress::bzip2()
        .with_data(b"Large text that compresses well...")
        .compress()
        .await?;

    assert!(!compressed.is_empty());

    // With maximum compression
    let max_compressed = Compress::bzip2()
        .with_data(b"Large file data that should compress really well with maximum settings")
        .max_compression()
        .compress()
        .await?;

    assert!(!max_compressed.is_empty());

    // Decompress
    let original = Compress::bzip2().with_data(compressed).decompress().await?;

    assert_eq!(original, b"Large text that compresses well...");

    Ok(())
}

#[tokio::test]
async fn test_compression_with_encryption() -> Result<(), Box<dyn std::error::Error>> {
    let master_key = [5u8; 32]; // Test key

    // Compress then encrypt in the cipher builder
    let result = Cipher::aes()
        .with_key(
            Key::size(256u32.bits())
                .with_store(FileKeyStore::at("/tmp/test_keys_compress").with_master_key(master_key))
                .with_namespace("app")
                .version(1),
        )
        .with_compression(Compress::bzip2().max_compression())
        .with_data(b"Large sensitive data that compresses well...")
        .encrypt()
        .await?;

    // Decrypt then decompress automatically
    let original = Cipher::aes()
        .with_key(
            Key::size(256u32.bits())
                .with_store(FileKeyStore::at("/tmp/test_keys_compress").with_master_key(master_key))
                .with_namespace("app")
                .version(1),
        )
        .with_compression(Compress::bzip2().max_compression())
        .with_ciphertext(result)
        .decrypt()
        .await?;

    assert_eq!(original, b"Large sensitive data that compresses well...");
    Ok(())
}

// Helper to clean up test directories
#[tokio::test]
async fn cleanup_test_dirs() {
    let _ = std::fs::remove_dir_all("/tmp/test_keys");
    let _ = std::fs::remove_dir_all("/tmp/test_keys_2pass");
    let _ = std::fs::remove_dir_all("/tmp/test_keys_batch");
    let _ = std::fs::remove_dir_all("/tmp/test_keys_integrated");
    let _ = std::fs::remove_dir_all("/tmp/test_keys_compress");
}
