//! Unit tests for key management and key store functionality

use cryypt::prelude::*;
use std::fs;

#[tokio::test]
async fn test_file_key_store_basic_operations() -> Result<(), Box<dyn std::error::Error>> {
    let test_dir = "/tmp/key_test_file_store";
    let master_key = [1u8; 32];

    fs::create_dir_all(test_dir)?;

    // Test key usage through encryption/decryption
    let test_data = b"Key store test data";

    // Encrypt with generated key
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

    // Decrypt with same key (should be retrieved from store)
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

    assert_eq!(plaintext, test_data);

    fs::remove_dir_all(test_dir).ok();
    Ok(())
}

#[tokio::test]
async fn test_file_key_store_different_namespaces() -> Result<(), Box<dyn std::error::Error>> {
    let test_dir = "/tmp/key_test_namespaces";
    let master_key = [2u8; 32];
    let test_data = b"Different namespaces test";

    fs::create_dir_all(test_dir)?;

    // Encrypt with key in namespace1
    let ciphertext1 = Cipher::aes()
        .with_key(
            Key::size(256.bits())
                .with_store(FileKeyStore::at(test_dir).with_master_key(master_key))
                .with_namespace("namespace1")
                .version(1),
        )
        .with_data(test_data)
        .encrypt()
        .await?;

    // Encrypt same data with key in namespace2
    let ciphertext2 = Cipher::aes()
        .with_key(
            Key::size(256.bits())
                .with_store(FileKeyStore::at(test_dir).with_master_key(master_key))
                .with_namespace("namespace2")
                .version(1),
        )
        .with_data(test_data)
        .encrypt()
        .await?;

    // Ciphertexts should be different (different keys)
    assert_ne!(ciphertext1.to_bytes(), ciphertext2.to_bytes());

    // Each should decrypt correctly with its own namespace
    let plaintext1 = Cipher::aes()
        .with_key(
            Key::size(256.bits())
                .with_store(FileKeyStore::at(test_dir).with_master_key(master_key))
                .with_namespace("namespace1")
                .version(1),
        )
        .with_ciphertext(ciphertext1.to_bytes())
        .decrypt()
        .await?;

    let plaintext2 = Cipher::aes()
        .with_key(
            Key::size(256.bits())
                .with_store(FileKeyStore::at(test_dir).with_master_key(master_key))
                .with_namespace("namespace2")
                .version(1),
        )
        .with_ciphertext(ciphertext2.to_bytes())
        .decrypt()
        .await?;

    assert_eq!(plaintext1, test_data);
    assert_eq!(plaintext2, test_data);

    fs::remove_dir_all(test_dir).ok();
    Ok(())
}

#[tokio::test]
async fn test_file_key_store_different_versions() -> Result<(), Box<dyn std::error::Error>> {
    let test_dir = "/tmp/key_test_versions";
    let master_key = [3u8; 32];
    let test_data = b"Different versions test";

    fs::create_dir_all(test_dir)?;

    // Encrypt with version 1
    let ciphertext_v1 = Cipher::aes()
        .with_key(
            Key::size(256.bits())
                .with_store(FileKeyStore::at(test_dir).with_master_key(master_key))
                .with_namespace("test")
                .version(1),
        )
        .with_data(test_data)
        .encrypt()
        .await?;

    // Encrypt with version 2
    let ciphertext_v2 = Cipher::aes()
        .with_key(
            Key::size(256.bits())
                .with_store(FileKeyStore::at(test_dir).with_master_key(master_key))
                .with_namespace("test")
                .version(2),
        )
        .with_data(test_data)
        .encrypt()
        .await?;

    // Should produce different ciphertexts
    assert_ne!(ciphertext_v1.to_bytes(), ciphertext_v2.to_bytes());

    // Each should decrypt correctly with its own version
    let plaintext_v1 = Cipher::aes()
        .with_key(
            Key::size(256.bits())
                .with_store(FileKeyStore::at(test_dir).with_master_key(master_key))
                .with_namespace("test")
                .version(1),
        )
        .with_ciphertext(ciphertext_v1.to_bytes())
        .decrypt()
        .await?;

    let plaintext_v2 = Cipher::aes()
        .with_key(
            Key::size(256.bits())
                .with_store(FileKeyStore::at(test_dir).with_master_key(master_key))
                .with_namespace("test")
                .version(2),
        )
        .with_ciphertext(ciphertext_v2.to_bytes())
        .decrypt()
        .await?;

    assert_eq!(plaintext_v1, test_data);
    assert_eq!(plaintext_v2, test_data);

    fs::remove_dir_all(test_dir).ok();
    Ok(())
}

#[tokio::test]
async fn test_file_key_store_different_master_keys() -> Result<(), Box<dyn std::error::Error>> {
    let test_dir = "/tmp/key_test_master_keys";
    let master_key1 = [4u8; 32];
    let master_key2 = [5u8; 32];
    let test_data = b"Different master keys test";

    fs::create_dir_all(test_dir)?;

    // Encrypt with first master key
    let ciphertext1 = Cipher::aes()
        .with_key(
            Key::size(256.bits())
                .with_store(FileKeyStore::at(test_dir).with_master_key(master_key1))
                .with_namespace("test")
                .version(1),
        )
        .with_data(test_data)
        .encrypt()
        .await?;

    // Encrypt with second master key (same namespace/version)
    let ciphertext2 = Cipher::aes()
        .with_key(
            Key::size(256.bits())
                .with_store(FileKeyStore::at(test_dir).with_master_key(master_key2))
                .with_namespace("test")
                .version(1),
        )
        .with_data(test_data)
        .encrypt()
        .await?;

    // Should produce different ciphertexts due to different master keys
    assert_ne!(ciphertext1.to_bytes(), ciphertext2.to_bytes());

    // Each should decrypt only with its corresponding master key
    let plaintext1 = Cipher::aes()
        .with_key(
            Key::size(256.bits())
                .with_store(FileKeyStore::at(test_dir).with_master_key(master_key1))
                .with_namespace("test")
                .version(1),
        )
        .with_ciphertext(ciphertext1.to_bytes())
        .decrypt()
        .await?;

    assert_eq!(plaintext1, test_data);

    // Trying to decrypt ciphertext1 with master_key2 should fail or give wrong result
    let result = Cipher::aes()
        .with_key(
            Key::size(256.bits())
                .with_store(FileKeyStore::at(test_dir).with_master_key(master_key2))
                .with_namespace("test")
                .version(1),
        )
        .with_ciphertext(ciphertext1.to_bytes())
        .decrypt()
        .await;

    // Should either fail or decrypt to something different
    match result {
        Ok(plaintext) => assert_ne!(plaintext, test_data),
        Err(_) => {} // Failure is also acceptable
    }

    fs::remove_dir_all(test_dir).ok();
    Ok(())
}

#[tokio::test]
async fn test_raw_key_builder() -> Result<(), Box<dyn std::error::Error>> {
    let raw_key_data = vec![42u8; 32];
    let test_data = b"Raw key test";

    // Use raw key for encryption
    let ciphertext = Cipher::aes()
        .with_key(Key::from_bytes(raw_key_data.clone()))
        .with_data(test_data)
        .encrypt()
        .await?;

    // Decrypt with same raw key
    let plaintext = Cipher::aes()
        .with_key(Key::from_bytes(raw_key_data))
        .with_ciphertext(ciphertext.to_bytes())
        .decrypt()
        .await?;

    assert_eq!(plaintext, test_data);

    Ok(())
}

#[tokio::test]
async fn test_key_persistence() -> Result<(), Box<dyn std::error::Error>> {
    let test_dir = "/tmp/key_test_persistence";
    let master_key = [7u8; 32];
    let test_data = b"Persistence test";

    fs::create_dir_all(test_dir)?;

    // Encrypt data
    let ciphertext = Cipher::aes()
        .with_key(
            Key::size(256.bits())
                .with_store(FileKeyStore::at(test_dir).with_master_key(master_key))
                .with_namespace("persistent")
                .version(1),
        )
        .with_data(test_data)
        .encrypt()
        .await?;

    // Create new process simulation - decrypt with fresh store instance
    let plaintext = Cipher::aes()
        .with_key(
            Key::size(256.bits())
                .with_store(FileKeyStore::at(test_dir).with_master_key(master_key))
                .with_namespace("persistent")
                .version(1),
        )
        .with_ciphertext(ciphertext.to_bytes())
        .decrypt()
        .await?;

    assert_eq!(plaintext, test_data);

    fs::remove_dir_all(test_dir).ok();
    Ok(())
}

#[tokio::test]
async fn test_file_key_store_invalid_directory() {
    let invalid_dir = "/this/path/should/not/exist/and/not/be/creatable";
    let master_key = [8u8; 32];
    let test_data = b"Invalid directory test";

    let result = Cipher::aes()
        .with_key(
            Key::size(256.bits())
                .with_store(FileKeyStore::at(invalid_dir).with_master_key(master_key))
                .with_namespace("test")
                .version(1),
        )
        .with_data(test_data)
        .encrypt()
        .await;

    assert!(result.is_err());
}

#[tokio::test]
async fn test_keychain_store_basic() -> Result<(), Box<dyn std::error::Error>> {
    // Note: This test might fail on systems without keychain support
    let test_data = b"Keychain test data";

    let result = Cipher::aes()
        .with_key(
            Key::size(256.bits())
                .with_store(KeychainStore::for_app("CryyptTestApp"))
                .with_namespace("test")
                .version(1),
        )
        .with_data(test_data)
        .encrypt()
        .await;

    match result {
        Ok(ciphertext) => {
            // If successful, try to decrypt
            let plaintext = Cipher::aes()
                .with_key(
                    Key::size(256.bits())
                        .with_store(KeychainStore::for_app("CryyptTestApp"))
                        .with_namespace("test")
                        .version(1),
                )
                .with_ciphertext(ciphertext.to_bytes())
                .decrypt()
                .await?;

            assert_eq!(plaintext, test_data);
        }
        Err(_) => {
            // Keychain might not be available in test environment
            println!("Keychain not available in test environment");
        }
    }

    Ok(())
}

#[tokio::test]
async fn test_concurrent_key_access() -> Result<(), Box<dyn std::error::Error>> {
    let test_dir = "/tmp/key_test_concurrent";
    let master_key = [12u8; 32];
    let test_data = b"Concurrent test";

    fs::create_dir_all(test_dir)?;

    // Access the same key concurrently for encryption
    let futures = (0..5).map(|i| {
        let data = format!("data_{}", i);
        async move {
            Cipher::aes()
                .with_key(
                    Key::size(256.bits())
                        .with_store(FileKeyStore::at(test_dir).with_master_key(master_key))
                        .with_namespace("concurrent")
                        .version(1),
                )
                .with_data(data.as_bytes())
                .encrypt()
                .await
        }
    });

    let results: Vec<_> = futures::future::join_all(futures).await;

    // All should succeed
    for result in &results {
        assert!(result.is_ok());
    }

    // Decrypt all results
    for (i, result) in results.iter().enumerate() {
        let ciphertext = result.as_ref().unwrap();
        let plaintext = Cipher::aes()
            .with_key(
                Key::size(256.bits())
                    .with_store(FileKeyStore::at(test_dir).with_master_key(master_key))
                    .with_namespace("concurrent")
                    .version(1),
            )
            .with_ciphertext(ciphertext.to_bytes())
            .decrypt()
            .await?;

        let expected = format!("data_{}", i);
        assert_eq!(plaintext, expected.as_bytes());
    }

    fs::remove_dir_all(test_dir).ok();
    Ok(())
}

#[tokio::test]
async fn test_key_consistency() -> Result<(), Box<dyn std::error::Error>> {
    let test_dir = "/tmp/key_test_consistency";
    let master_key = [17u8; 32];
    let test_data = b"Consistency test";

    fs::create_dir_all(test_dir)?;

    // Encrypt the same data multiple times with same key parameters
    let mut ciphertexts = Vec::new();
    for _ in 0..5 {
        let ciphertext = Cipher::aes()
            .with_key(
                Key::size(256.bits())
                    .with_store(FileKeyStore::at(test_dir).with_master_key(master_key))
                    .with_namespace("consistency")
                    .version(1),
            )
            .with_data(test_data)
            .encrypt()
            .await?;
        ciphertexts.push(ciphertext);
    }

    // All should decrypt to the same plaintext
    for ciphertext in ciphertexts {
        let plaintext = Cipher::aes()
            .with_key(
                Key::size(256.bits())
                    .with_store(FileKeyStore::at(test_dir).with_master_key(master_key))
                    .with_namespace("consistency")
                    .version(1),
            )
            .with_ciphertext(ciphertext.to_bytes())
            .decrypt()
            .await?;

        assert_eq!(plaintext, test_data);
    }

    fs::remove_dir_all(test_dir).ok();
    Ok(())
}

#[tokio::test]
async fn test_special_characters_in_namespace() -> Result<(), Box<dyn std::error::Error>> {
    let test_dir = "/tmp/key_test_special_chars";
    let master_key = [16u8; 32];
    let test_data = b"Special chars test";

    fs::create_dir_all(test_dir)?;

    // Test with special characters in namespace
    let ciphertext = Cipher::aes()
        .with_key(
            Key::size(256.bits())
                .with_store(FileKeyStore::at(test_dir).with_master_key(master_key))
                .with_namespace("test-namespace_123")
                .version(1),
        )
        .with_data(test_data)
        .encrypt()
        .await?;

    let plaintext = Cipher::aes()
        .with_key(
            Key::size(256.bits())
                .with_store(FileKeyStore::at(test_dir).with_master_key(master_key))
                .with_namespace("test-namespace_123")
                .version(1),
        )
        .with_ciphertext(ciphertext.to_bytes())
        .decrypt()
        .await?;

    assert_eq!(plaintext, test_data);

    fs::remove_dir_all(test_dir).ok();
    Ok(())
}

#[tokio::test]
async fn test_zero_version() -> Result<(), Box<dyn std::error::Error>> {
    let test_dir = "/tmp/key_test_zero_version";
    let master_key = [14u8; 32];
    let test_data = b"Zero version test";

    fs::create_dir_all(test_dir)?;

    // Test with version 0
    let ciphertext = Cipher::aes()
        .with_key(
            Key::size(256.bits())
                .with_store(FileKeyStore::at(test_dir).with_master_key(master_key))
                .with_namespace("test")
                .version(0),
        )
        .with_data(test_data)
        .encrypt()
        .await?;

    let plaintext = Cipher::aes()
        .with_key(
            Key::size(256.bits())
                .with_store(FileKeyStore::at(test_dir).with_master_key(master_key))
                .with_namespace("test")
                .version(0),
        )
        .with_ciphertext(ciphertext.to_bytes())
        .decrypt()
        .await?;

    assert_eq!(plaintext, test_data);

    fs::remove_dir_all(test_dir).ok();
    Ok(())
}

#[tokio::test]
async fn test_large_version_number() -> Result<(), Box<dyn std::error::Error>> {
    let test_dir = "/tmp/key_test_large_version";
    let master_key = [15u8; 32];
    let test_data = b"Large version test";

    fs::create_dir_all(test_dir)?;

    // Test with large version number
    let ciphertext = Cipher::aes()
        .with_key(
            Key::size(256.bits())
                .with_store(FileKeyStore::at(test_dir).with_master_key(master_key))
                .with_namespace("test")
                .version(999999),
        )
        .with_data(test_data)
        .encrypt()
        .await?;

    let plaintext = Cipher::aes()
        .with_key(
            Key::size(256.bits())
                .with_store(FileKeyStore::at(test_dir).with_master_key(master_key))
                .with_namespace("test")
                .version(999999),
        )
        .with_ciphertext(ciphertext.to_bytes())
        .decrypt()
        .await?;

    assert_eq!(plaintext, test_data);

    fs::remove_dir_all(test_dir).ok();
    Ok(())
}
