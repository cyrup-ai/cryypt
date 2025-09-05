//! Test that our decomposed hash modules work correctly

use cryypt_hashing::api::{Blake2bBuilder, Hash, Sha3_256Builder, Sha256Builder};

#[tokio::test]
async fn test_sha256_builder() {
    let data = b"test data";
    let result = Hash::sha256().compute(data.to_vec()).await;
    assert!(result.is_ok());
    let hash = result.expect("SHA-256 hash computation should succeed");
    assert_eq!(hash.len(), 32); // SHA-256 produces 32 bytes
}

#[tokio::test]
async fn test_sha256_with_key() {
    let data = b"test data";
    let key = b"secret key";
    let result = Hash::sha256()
        .with_key(key.to_vec())
        .compute(data.to_vec())
        .await;
    assert!(result.is_ok());
    let hash = result.expect("HMAC-SHA256 hash computation should succeed");
    assert_eq!(hash.len(), 32); // HMAC-SHA256 produces 32 bytes
}

#[tokio::test]
async fn test_sha3_256_builder() {
    let data = b"test data";
    let result = Hash::sha3_256().compute(data.to_vec()).await;
    assert!(result.is_ok());
    let hash = result.expect("SHA3-256 hash computation should succeed");
    assert_eq!(hash.len(), 32); // SHA3-256 produces 32 bytes
}

#[tokio::test]
async fn test_blake2b_builder() {
    let data = b"test data";
    let result = Hash::blake2b().compute(data.to_vec()).await;
    assert!(result.is_ok());
    let hash = result.expect("Blake2b hash computation should succeed");
    assert_eq!(hash.len(), 64); // Blake2b-512 produces 64 bytes
}

#[tokio::test]
async fn test_blake2b_with_custom_size() {
    let data = b"test data";
    let result = Hash::blake2b()
        .with_output_size(32)
        .compute(data.to_vec())
        .await;
    assert!(result.is_ok());
    let hash = result.expect("Blake2b with custom size should succeed");
    assert_eq!(hash.len(), 32); // Custom size
}

#[test]
fn test_direct_builder_creation() {
    // Test that we can create builders directly
    let _sha256 = Sha256Builder::new();
    let _sha3_256 = Sha3_256Builder::new();
    let _blake2b = Blake2bBuilder::new();
}
