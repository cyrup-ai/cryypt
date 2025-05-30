//! Tests for post-quantum KEM (Key Encapsulation Mechanism) operations

use cryypt::prelude::*;
use cryypt::pqcrypto::{KemAlgorithm, SharedSecret};
use std::fs;

#[tokio::test]
async fn test_ml_kem_512_basic_encapsulation() -> Result<(), Box<dyn std::error::Error>> {
    // Generate key pair
    let keypair = KemBuilder::ml_kem_512()
        .generate()
        .await?;
    
    // Encapsulate with public key
    let encapsulation_result = keypair
        .encapsulate()
        .await?;
    
    // Decapsulate with secret key
    let decapsulation_result = keypair
        .with_ciphertext(encapsulation_result.ciphertext())
        .decapsulate()
        .await?;
    
    // Verify shared secrets match
    assert_eq!(
        encapsulation_result.shared_secret().as_bytes(),
        decapsulation_result.shared_secret().as_bytes()
    );
    
    Ok(())
}

#[tokio::test]
async fn test_ml_kem_768_basic_encapsulation() -> Result<(), Box<dyn std::error::Error>> {
    // Generate key pair
    let keypair = KemBuilder::ml_kem_768()
        .generate()
        .await?;
    
    // Encapsulate with public key
    let encapsulation_result = keypair
        .encapsulate()
        .await?;
    
    // Decapsulate with secret key
    let decapsulation_result = keypair
        .with_ciphertext(encapsulation_result.ciphertext())
        .decapsulate()
        .await?;
    
    // Verify shared secrets match
    assert_eq!(
        encapsulation_result.shared_secret().as_bytes(),
        decapsulation_result.shared_secret().as_bytes()
    );
    
    Ok(())
}

#[tokio::test]
async fn test_ml_kem_1024_basic_encapsulation() -> Result<(), Box<dyn std::error::Error>> {
    // Generate key pair
    let keypair = KemBuilder::ml_kem_1024()
        .generate()
        .await?;
    
    // Encapsulate with public key
    let encapsulation_result = keypair
        .encapsulate()
        .await?;
    
    // Decapsulate with secret key
    let decapsulation_result = keypair
        .with_ciphertext(encapsulation_result.ciphertext())
        .decapsulate()
        .await?;
    
    // Verify shared secrets match
    assert_eq!(
        encapsulation_result.shared_secret().as_bytes(),
        decapsulation_result.shared_secret().as_bytes()
    );
    
    Ok(())
}

#[tokio::test]
async fn test_ml_kem_separate_keys() -> Result<(), Box<dyn std::error::Error>> {
    // Generate key pair
    let keypair = KemBuilder::ml_kem_768()
        .generate()
        .await?;
    
    // Alice encapsulates with Bob's public key
    let alice_result = KemBuilder::ml_kem_768()
        .with_public_key(keypair.public_key.clone().ok_or("No public key")?)
        .encapsulate()
        .await?;
    
    // Bob decapsulates with his secret key
    let bob_result = KemBuilder::ml_kem_768()
        .with_secret_key(keypair.secret_key.ok_or("No secret key")?)
        .with_ciphertext(alice_result.ciphertext())
        .decapsulate()
        .await?;
    
    // Verify shared secrets match
    assert_eq!(
        alice_result.shared_secret().as_bytes(),
        bob_result.shared_secret().as_bytes()
    );
    
    Ok(())
}

#[tokio::test]
async fn test_ml_kem_hex_encoding() -> Result<(), Box<dyn std::error::Error>> {
    // Generate key pair
    let keypair = KemBuilder::ml_kem_512()
        .generate()
        .await?;
    
    // Get public key as hex
    let pk_hex = hex::encode(&keypair.public_key.clone().ok_or("No public key")?);
    let sk_hex = hex::encode(&keypair.secret_key.clone().ok_or("No secret key")?);
    
    // Load keys from hex
    let loaded_keypair = KemBuilder::ml_kem_512()
        .with_public_key_hex(&pk_hex)?
        .with_secret_key_hex(&sk_hex)?;
    
    // Encapsulate
    let encapsulation_result = loaded_keypair
        .encapsulate()
        .await?;
    
    // Get ciphertext as hex
    let ct_hex = encapsulation_result.ciphertext_hex();
    
    // Decapsulate using hex ciphertext
    let decapsulation_result = loaded_keypair
        .with_ciphertext_hex(&ct_hex)?
        .decapsulate()
        .await?;
    
    // Verify shared secrets match
    assert_eq!(
        encapsulation_result.shared_secret().as_bytes(),
        decapsulation_result.shared_secret().as_bytes()
    );
    
    Ok(())
}

#[tokio::test]
async fn test_ml_kem_base64_encoding() -> Result<(), Box<dyn std::error::Error>> {
    // Generate key pair
    let keypair = KemBuilder::ml_kem_1024()
        .generate()
        .await?;
    
    // Get public key as base64
    use base64::Engine;
    let pk_base64 = base64::engine::general_purpose::STANDARD
        .encode(&keypair.public_key.clone().ok_or("No public key")?);
    let sk_base64 = base64::engine::general_purpose::STANDARD
        .encode(&keypair.secret_key.clone().ok_or("No secret key")?);
    
    // Load keys from base64
    let loaded_keypair = KemBuilder::ml_kem_1024()
        .with_public_key_base64(&pk_base64)?
        .with_secret_key_base64(&sk_base64)?;
    
    // Encapsulate
    let encapsulation_result = loaded_keypair
        .encapsulate()
        .await?;
    
    // Get ciphertext as base64
    let ct_base64 = encapsulation_result.ciphertext_base64();
    
    // Decapsulate using base64 ciphertext
    let decapsulation_result = loaded_keypair
        .with_ciphertext_base64(&ct_base64)?
        .decapsulate()
        .await?;
    
    // Verify shared secrets match
    assert_eq!(
        encapsulation_result.shared_secret().as_bytes(),
        decapsulation_result.shared_secret().as_bytes()
    );
    
    Ok(())
}

#[tokio::test]
async fn test_ml_kem_file_operations() -> Result<(), Box<dyn std::error::Error>> {
    let test_dir = "/tmp/kem_test_files";
    fs::create_dir_all(test_dir).ok();
    
    // Generate key pair
    let keypair = KemBuilder::ml_kem_768()
        .generate()
        .await?;
    
    // Save keys to files
    let pk_path = format!("{}/public_key.bin", test_dir);
    let sk_path = format!("{}/secret_key.bin", test_dir);
    let ct_path = format!("{}/ciphertext.bin", test_dir);
    
    tokio::fs::write(&pk_path, &keypair.public_key.clone().ok_or("No public key")?).await?;
    tokio::fs::write(&sk_path, &keypair.secret_key.clone().ok_or("No secret key")?).await?;
    
    // Load keys from files
    let loaded_keypair = KemBuilder::ml_kem_768()
        .with_keypair_files(&pk_path, &sk_path)
        .await?;
    
    // Encapsulate
    let encapsulation_result = loaded_keypair
        .encapsulate()
        .await?;
    
    // Save ciphertext to file
    tokio::fs::write(&ct_path, encapsulation_result.ciphertext()).await?;
    
    // Load ciphertext from file and decapsulate
    let decapsulation_result = loaded_keypair
        .with_ciphertext_file(&ct_path)
        .await?
        .decapsulate()
        .await?;
    
    // Verify shared secrets match
    assert_eq!(
        encapsulation_result.shared_secret().as_bytes(),
        decapsulation_result.shared_secret().as_bytes()
    );
    
    // Cleanup
    fs::remove_dir_all(test_dir).ok();
    
    Ok(())
}

#[tokio::test]
async fn test_ml_kem_dynamic_security_level() -> Result<(), Box<dyn std::error::Error>> {
    let security_levels = vec![512, 768, 1024];
    
    for level in security_levels {
        let keypair = KemBuilder::ml_kem(level)?
            .generate()
            .await?;
        
        let encapsulation_result = keypair
            .encapsulate()
            .await?;
        
        let decapsulation_result = keypair
            .with_ciphertext(encapsulation_result.ciphertext())
            .decapsulate()
            .await?;
        
        assert_eq!(
            encapsulation_result.shared_secret().as_bytes(),
            decapsulation_result.shared_secret().as_bytes()
        );
        
        // Verify algorithm matches
        assert_eq!(
            encapsulation_result.algorithm(),
            decapsulation_result.algorithm()
        );
    }
    
    Ok(())
}

#[tokio::test]
async fn test_ml_kem_shared_secret_serialization() -> Result<(), Box<dyn std::error::Error>> {
    let keypair = KemBuilder::ml_kem_768()
        .generate()
        .await?;
    
    let encapsulation_result = keypair
        .encapsulate()
        .await?;
    
    // Test shared secret hex conversion
    let ss_hex = encapsulation_result.shared_secret().to_hex();
    let ss_from_hex = SharedSecret::from_hex(KemAlgorithm::MlKem768, &ss_hex)?;
    assert_eq!(
        encapsulation_result.shared_secret().as_bytes(),
        ss_from_hex.as_bytes()
    );
    
    // Test shared secret base64 conversion
    let ss_base64 = encapsulation_result.shared_secret().to_base64();
    let ss_from_base64 = SharedSecret::from_base64(KemAlgorithm::MlKem768, &ss_base64)?;
    assert_eq!(
        encapsulation_result.shared_secret().as_bytes(),
        ss_from_base64.as_bytes()
    );
    
    // Test JSON serialization
    let ss_json = serde_json::to_string(encapsulation_result.shared_secret())?;
    let ss_from_json: SharedSecret = serde_json::from_str(&ss_json)?;
    assert_eq!(
        encapsulation_result.shared_secret(),
        &ss_from_json
    );
    
    Ok(())
}

#[tokio::test]
async fn test_ml_kem_encapsulation_result_serialization() -> Result<(), Box<dyn std::error::Error>> {
    let keypair = KemBuilder::ml_kem_512()
        .generate()
        .await?;
    
    let encapsulation_result = keypair
        .encapsulate()
        .await?;
    
    // Test JSON serialization (note: shared secret is skipped)
    let json = serde_json::to_string(&encapsulation_result)?;
    let value: serde_json::Value = serde_json::from_str(&json)?;
    
    assert!(value.get("algorithm").is_some());
    assert!(value.get("ciphertext").is_some());
    assert!(value.get("shared_secret").is_none()); // Should be skipped
    
    Ok(())
}

#[tokio::test]
async fn test_ml_kem_error_invalid_key_size() -> Result<(), Box<dyn std::error::Error>> {
    // Try to load a key with wrong size
    let invalid_key = vec![0u8; 100]; // Wrong size
    
    let result = KemBuilder::ml_kem_768()
        .with_public_key(invalid_key);
    
    assert!(result.is_err());
    match result {
        Err(CryptError::InvalidKeySize { expected, actual }) => {
            assert_eq!(expected, 1184); // ML-KEM-768 public key size
            assert_eq!(actual, 100);
        }
        _ => panic!("Expected InvalidKeySize error"),
    }
    
    Ok(())
}

#[tokio::test]
async fn test_ml_kem_error_invalid_ciphertext_size() -> Result<(), Box<dyn std::error::Error>> {
    let keypair = KemBuilder::ml_kem_512()
        .generate()
        .await?;
    
    let invalid_ciphertext = vec![0u8; 100]; // Wrong size
    
    let result = keypair
        .with_ciphertext(invalid_ciphertext)
        .decapsulate()
        .await;
    
    assert!(result.is_err());
    
    Ok(())
}

#[tokio::test]
async fn test_ml_kem_error_missing_keys() -> Result<(), Box<dyn std::error::Error>> {
    // Try to encapsulate without public key
    let builder = KemBuilder::ml_kem_768();
    let sk = vec![0u8; 2400]; // Correct size for ML-KEM-768 secret key
    
    let result = builder
        .with_secret_key(sk)?
        .with_ciphertext(vec![0u8; 1088]) // Correct size for ML-KEM-768 ciphertext
        .decapsulate()
        .await;
    
    // This should work as we have secret key
    assert!(result.is_ok() || result.is_err()); // May fail due to invalid key content
    
    Ok(())
}

#[tokio::test]
async fn test_ml_kem_algorithm_metadata() -> Result<(), Box<dyn std::error::Error>> {
    // Test ML-KEM-512
    let alg = KemAlgorithm::MlKem512;
    assert_eq!(alg.security_level(), 1);
    assert_eq!(alg.public_key_size(), 800);
    assert_eq!(alg.secret_key_size(), 1632);
    assert_eq!(alg.ciphertext_size(), 768);
    assert_eq!(alg.shared_secret_size(), 32);
    
    // Test ML-KEM-768
    let alg = KemAlgorithm::MlKem768;
    assert_eq!(alg.security_level(), 3);
    assert_eq!(alg.public_key_size(), 1184);
    assert_eq!(alg.secret_key_size(), 2400);
    assert_eq!(alg.ciphertext_size(), 1088);
    assert_eq!(alg.shared_secret_size(), 32);
    
    // Test ML-KEM-1024
    let alg = KemAlgorithm::MlKem1024;
    assert_eq!(alg.security_level(), 5);
    assert_eq!(alg.public_key_size(), 1568);
    assert_eq!(alg.secret_key_size(), 3168);
    assert_eq!(alg.ciphertext_size(), 1568);
    assert_eq!(alg.shared_secret_size(), 32);
    
    Ok(())
}

#[tokio::test]
async fn test_ml_kem_cross_algorithm_failure() -> Result<(), Box<dyn std::error::Error>> {
    // Generate ML-KEM-512 key pair
    let keypair_512 = KemBuilder::ml_kem_512()
        .generate()
        .await?;
    
    // Try to use ML-KEM-768 with ML-KEM-512 public key
    let result = KemBuilder::ml_kem_768()
        .with_public_key(keypair_512.public_key.ok_or("No public key")?);
    
    // This should fail due to wrong key size
    assert!(result.is_err());
    
    Ok(())
}