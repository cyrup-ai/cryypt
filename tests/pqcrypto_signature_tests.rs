//! Tests for post-quantum digital signature operations

use cryypt::prelude::*;
use cryypt::pqcrypto::SignatureAlgorithm;
use std::fs;

#[tokio::test]
async fn test_ml_dsa_44_basic_signature() -> Result<(), Box<dyn std::error::Error>> {
    // Generate key pair
    let keypair = SignatureBuilder::ml_dsa_44()
        .generate()
        .await?;
    
    // Sign message
    let message = b"Hello, post-quantum world!";
    let signature = keypair
        .with_message(message)
        .sign()
        .await?;
    
    // Verify signature
    let verification = keypair
        .with_message(message)
        .with_signature(signature.signature())
        .verify()
        .await?;
    
    assert!(verification.is_valid());
    
    Ok(())
}

#[tokio::test]
async fn test_ml_dsa_65_basic_signature() -> Result<(), Box<dyn std::error::Error>> {
    // Generate key pair
    let keypair = SignatureBuilder::ml_dsa_65()
        .generate()
        .await?;
    
    // Sign message
    let message = b"Testing ML-DSA-65 signatures";
    let signature = keypair
        .with_message(message)
        .sign()
        .await?;
    
    // Verify signature
    let verification = keypair
        .with_message(message)
        .with_signature(signature.signature())
        .verify()
        .await?;
    
    assert!(verification.is_valid());
    
    Ok(())
}

#[tokio::test]
async fn test_ml_dsa_87_basic_signature() -> Result<(), Box<dyn std::error::Error>> {
    // Generate key pair
    let keypair = SignatureBuilder::ml_dsa_87()
        .generate()
        .await?;
    
    // Sign message
    let message = b"High security ML-DSA-87 test";
    let signature = keypair
        .with_message(message)
        .sign()
        .await?;
    
    // Verify signature
    let verification = keypair
        .with_message(message)
        .with_signature(signature.signature())
        .verify()
        .await?;
    
    assert!(verification.is_valid());
    
    Ok(())
}

#[tokio::test]
async fn test_falcon_512_basic_signature() -> Result<(), Box<dyn std::error::Error>> {
    // Generate key pair
    let keypair = SignatureBuilder::falcon_512()
        .generate()
        .await?;
    
    // Sign message
    let message = b"FALCON-512 signature test";
    let signature = keypair
        .with_message(message)
        .sign()
        .await?;
    
    // Verify signature
    let verification = keypair
        .with_message(message)
        .with_signature(signature.signature())
        .verify()
        .await?;
    
    assert!(verification.is_valid());
    
    Ok(())
}

#[tokio::test]
async fn test_falcon_1024_basic_signature() -> Result<(), Box<dyn std::error::Error>> {
    // Generate key pair
    let keypair = SignatureBuilder::falcon_1024()
        .generate()
        .await?;
    
    // Sign message
    let message = b"FALCON-1024 high security test";
    let signature = keypair
        .with_message(message)
        .sign()
        .await?;
    
    // Verify signature
    let verification = keypair
        .with_message(message)
        .with_signature(signature.signature())
        .verify()
        .await?;
    
    assert!(verification.is_valid());
    
    Ok(())
}

#[tokio::test]
async fn test_sphincs_plus_variants() -> Result<(), Box<dyn std::error::Error>> {
    let variants = vec![
        "sha256-128f-simple",
        "sha256-128s-simple",
        "sha256-192f-simple",
        "sha256-192s-simple",
        "sha256-256f-simple",
        "sha256-256s-simple",
    ];
    
    for variant in variants {
        let keypair = SignatureBuilder::sphincs_plus(variant)?
            .generate()
            .await?;
        
        let message = format!("Testing SPHINCS+ variant: {}", variant);
        let signature = keypair
            .with_message(message.as_bytes())
            .sign()
            .await?;
        
        let verification = keypair
            .with_message(message.as_bytes())
            .with_signature(signature.signature())
            .verify()
            .await?;
        
        assert!(verification.is_valid(), "Failed for variant: {}", variant);
    }
    
    Ok(())
}

#[tokio::test]
async fn test_signature_separate_keys() -> Result<(), Box<dyn std::error::Error>> {
    // Generate key pair
    let keypair = SignatureBuilder::ml_dsa_65()
        .generate()
        .await?;
    
    let message = b"Message to be signed";
    
    // Alice signs with secret key
    let signature = SignatureBuilder::ml_dsa_65()
        .with_secret_key(keypair.secret_key.clone().ok_or("No secret key")?)?
        .with_message(message)
        .sign()
        .await?;
    
    // Bob verifies with public key
    let verification = SignatureBuilder::ml_dsa_65()
        .with_public_key(keypair.public_key.ok_or("No public key")?)?
        .with_message(message)
        .with_signature(signature.signature())
        .verify()
        .await?;
    
    assert!(verification.is_valid());
    
    Ok(())
}

#[tokio::test]
async fn test_signature_hex_encoding() -> Result<(), Box<dyn std::error::Error>> {
    // Generate key pair
    let keypair = SignatureBuilder::falcon_512()
        .generate()
        .await?;
    
    // Get keys as hex
    let pk_hex = hex::encode(&keypair.public_key.clone().ok_or("No public key")?);
    let sk_hex = hex::encode(&keypair.secret_key.clone().ok_or("No secret key")?);
    
    // Load keys from hex
    let loaded_keypair = SignatureBuilder::falcon_512()
        .with_public_key_hex(&pk_hex)?
        .with_secret_key_hex(&sk_hex)?;
    
    // Sign message
    let message = b"Testing hex encoding";
    let signature = loaded_keypair
        .with_message(message)
        .sign()
        .await?;
    
    // Get signature as hex
    let sig_hex = signature.signature_hex();
    
    // Verify using hex signature
    let verification = loaded_keypair
        .with_message(message)
        .with_signature_hex(&sig_hex)?
        .verify()
        .await?;
    
    assert!(verification.is_valid());
    
    Ok(())
}

#[tokio::test]
async fn test_signature_base64_encoding() -> Result<(), Box<dyn std::error::Error>> {
    // Generate key pair
    let keypair = SignatureBuilder::ml_dsa_87()
        .generate()
        .await?;
    
    // Get keys as base64
    use base64::Engine;
    let pk_base64 = base64::engine::general_purpose::STANDARD
        .encode(&keypair.public_key.clone().ok_or("No public key")?);
    let sk_base64 = base64::engine::general_purpose::STANDARD
        .encode(&keypair.secret_key.clone().ok_or("No secret key")?);
    
    // Load keys from base64
    let loaded_keypair = SignatureBuilder::ml_dsa_87()
        .with_public_key_base64(&pk_base64)?
        .with_secret_key_base64(&sk_base64)?;
    
    // Sign message
    let message = b"Testing base64 encoding";
    let signature = loaded_keypair
        .with_message(message)
        .sign()
        .await?;
    
    // Get signature as base64
    let sig_base64 = signature.signature_base64();
    
    // Verify using base64 signature
    let verification = loaded_keypair
        .with_message(message)
        .with_signature_base64(&sig_base64)?
        .verify()
        .await?;
    
    assert!(verification.is_valid());
    
    Ok(())
}

#[tokio::test]
async fn test_signature_file_operations() -> Result<(), Box<dyn std::error::Error>> {
    let test_dir = "/tmp/signature_test_files";
    fs::create_dir_all(test_dir).ok();
    
    // Generate key pair
    let keypair = SignatureBuilder::ml_dsa_44()
        .generate()
        .await?;
    
    // Save keys to files
    let pk_path = format!("{}/public_key.bin", test_dir);
    let sk_path = format!("{}/secret_key.bin", test_dir);
    let msg_path = format!("{}/message.txt", test_dir);
    let sig_path = format!("{}/signature.bin", test_dir);
    
    tokio::fs::write(&pk_path, &keypair.public_key.clone().ok_or("No public key")?).await?;
    tokio::fs::write(&sk_path, &keypair.secret_key.clone().ok_or("No secret key")?).await?;
    
    // Write message to file
    let message = b"Message from file";
    tokio::fs::write(&msg_path, message).await?;
    
    // Load keys from files
    let loaded_keypair = SignatureBuilder::ml_dsa_44()
        .with_keypair_files(&pk_path, &sk_path)
        .await?;
    
    // Sign message from file
    let signature = loaded_keypair
        .with_message_file(&msg_path)
        .await?
        .sign()
        .await?;
    
    // Save signature to file
    tokio::fs::write(&sig_path, signature.signature()).await?;
    
    // Verify signature from files
    let verification = loaded_keypair
        .with_message_file(&msg_path)
        .await?
        .with_signature_file(&sig_path)
        .await?
        .verify()
        .await?;
    
    assert!(verification.is_valid());
    
    // Cleanup
    fs::remove_dir_all(test_dir).ok();
    
    Ok(())
}

#[tokio::test]
async fn test_signature_text_message() -> Result<(), Box<dyn std::error::Error>> {
    let keypair = SignatureBuilder::falcon_1024()
        .generate()
        .await?;
    
    let text_message = "This is a text message with UTF-8 characters: 你好世界 🌍";
    
    // Sign text message
    let signature = keypair
        .with_message_text(text_message)
        .sign()
        .await?;
    
    // Verify text message
    let verification = keypair
        .with_message_text(text_message)
        .with_signature(signature.signature())
        .verify()
        .await?;
    
    assert!(verification.is_valid());
    
    Ok(())
}

#[tokio::test]
async fn test_signature_hex_message() -> Result<(), Box<dyn std::error::Error>> {
    let keypair = SignatureBuilder::ml_dsa_65()
        .generate()
        .await?;
    
    let hex_message = "deadbeef0123456789abcdef";
    
    // Sign hex message
    let signature = keypair
        .with_message_hex(hex_message)?
        .sign()
        .await?;
    
    // Verify hex message
    let verification = keypair
        .with_message_hex(hex_message)?
        .with_signature(signature.signature())
        .verify()
        .await?;
    
    assert!(verification.is_valid());
    
    Ok(())
}

#[tokio::test]
async fn test_signature_base64_message() -> Result<(), Box<dyn std::error::Error>> {
    let keypair = SignatureBuilder::ml_dsa_44()
        .generate()
        .await?;
    
    let base64_message = "SGVsbG8gV29ybGQh"; // "Hello World!"
    
    // Sign base64 message
    let signature = keypair
        .with_message_base64(base64_message)?
        .sign()
        .await?;
    
    // Verify base64 message
    let verification = keypair
        .with_message_base64(base64_message)?
        .with_signature(signature.signature())
        .verify()
        .await?;
    
    assert!(verification.is_valid());
    
    Ok(())
}

#[tokio::test]
async fn test_signature_invalid_verification() -> Result<(), Box<dyn std::error::Error>> {
    let keypair = SignatureBuilder::ml_dsa_65()
        .generate()
        .await?;
    
    let message1 = b"Original message";
    let message2 = b"Different message";
    
    // Sign first message
    let signature = keypair
        .with_message(message1)
        .sign()
        .await?;
    
    // Try to verify with different message
    let verification = keypair
        .with_message(message2)
        .with_signature(signature.signature())
        .verify()
        .await?;
    
    assert!(!verification.is_valid());
    
    Ok(())
}

#[tokio::test]
async fn test_signature_wrong_public_key() -> Result<(), Box<dyn std::error::Error>> {
    let keypair1 = SignatureBuilder::falcon_512()
        .generate()
        .await?;
    
    let keypair2 = SignatureBuilder::falcon_512()
        .generate()
        .await?;
    
    let message = b"Test message";
    
    // Sign with first keypair
    let signature = keypair1
        .with_message(message)
        .sign()
        .await?;
    
    // Try to verify with different public key
    let verification = SignatureBuilder::falcon_512()
        .with_public_key(keypair2.public_key.ok_or("No public key")?)?
        .with_message(message)
        .with_signature(signature.signature())
        .verify()
        .await?;
    
    assert!(!verification.is_valid());
    
    Ok(())
}

#[tokio::test]
async fn test_signature_error_invalid_key_size() -> Result<(), Box<dyn std::error::Error>> {
    // Try to load a key with wrong size
    let invalid_key = vec![0u8; 100]; // Wrong size
    
    let result = SignatureBuilder::ml_dsa_65()
        .with_public_key(invalid_key);
    
    assert!(result.is_err());
    match result {
        Err(CryptError::InvalidKeySize { expected, actual }) => {
            assert_eq!(expected, 1952); // ML-DSA-65 public key size
            assert_eq!(actual, 100);
        }
        _ => panic!("Expected InvalidKeySize error"),
    }
    
    Ok(())
}

#[tokio::test]
async fn test_signature_algorithm_metadata() -> Result<(), Box<dyn std::error::Error>> {
    // Test ML-DSA
    let alg = SignatureAlgorithm::MlDsa44;
    assert_eq!(alg.security_level(), 2);
    assert_eq!(alg.public_key_size(), 1312);
    assert_eq!(alg.secret_key_size(), 2528);
    assert_eq!(alg.signature_size(), 2420);
    
    let alg = SignatureAlgorithm::MlDsa65;
    assert_eq!(alg.security_level(), 3);
    assert_eq!(alg.public_key_size(), 1952);
    assert_eq!(alg.secret_key_size(), 4000);
    assert_eq!(alg.signature_size(), 3293);
    
    // Test FALCON
    let alg = SignatureAlgorithm::Falcon512;
    assert_eq!(alg.security_level(), 1);
    assert_eq!(alg.public_key_size(), 897);
    assert_eq!(alg.secret_key_size(), 1281);
    assert_eq!(alg.signature_size(), 666);
    
    // Test SPHINCS+
    let alg = SignatureAlgorithm::SphincsShaSha256_128fSimple;
    assert_eq!(alg.security_level(), 1);
    assert!(alg.is_fast_variant());
    assert!(!alg.is_small_variant());
    
    let alg = SignatureAlgorithm::SphincsShaSha256_256sSimple;
    assert_eq!(alg.security_level(), 5);
    assert!(!alg.is_fast_variant());
    assert!(alg.is_small_variant());
    
    Ok(())
}

#[tokio::test]
async fn test_signature_result_serialization() -> Result<(), Box<dyn std::error::Error>> {
    let keypair = SignatureBuilder::ml_dsa_44()
        .generate()
        .await?;
    
    let message = b"Test message";
    let signature = keypair
        .with_message(message)
        .sign()
        .await?;
    
    // Test JSON serialization
    let json = serde_json::to_string(&signature)?;
    let value: serde_json::Value = serde_json::from_str(&json)?;
    
    assert!(value.get("algorithm").is_some());
    assert!(value.get("signature").is_some());
    assert!(value.get("message").is_none()); // Should be None for detached signatures
    assert!(signature.is_detached());
    
    Ok(())
}

#[tokio::test]
async fn test_verification_result_to_result() -> Result<(), Box<dyn std::error::Error>> {
    let keypair = SignatureBuilder::falcon_1024()
        .generate()
        .await?;
    
    let message = b"Test message";
    let signature = keypair
        .with_message(message)
        .sign()
        .await?;
    
    // Valid verification
    let verification = keypair
        .with_message(message)
        .with_signature(signature.signature())
        .verify()
        .await?;
    
    let result = verification.to_result();
    assert!(result.is_ok());
    
    // Invalid verification
    let wrong_message = b"Wrong message";
    let invalid_verification = keypair
        .with_message(wrong_message)
        .with_signature(signature.signature())
        .verify()
        .await?;
    
    let result = invalid_verification.to_result();
    assert!(result.is_err());
    
    Ok(())
}

#[tokio::test]
async fn test_dynamic_security_level_selection() -> Result<(), Box<dyn std::error::Error>> {
    // Test ML-DSA with different notations
    let keypair1 = SignatureBuilder::ml_dsa(44)?
        .generate()
        .await?;
    
    let keypair2 = SignatureBuilder::ml_dsa(2)?  // Security level 2
        .generate()
        .await?;
    
    // Test FALCON with different notations
    let keypair3 = SignatureBuilder::falcon(512)?
        .generate()
        .await?;
    
    let keypair4 = SignatureBuilder::falcon(1)?  // Security level 1
        .generate()
        .await?;
    
    // All should work
    let message = b"Test";
    for keypair in [keypair1, keypair2, keypair3, keypair4] {
        let signature = keypair
            .with_message(message)
            .sign()
            .await?;
        
        let verification = keypair
            .with_message(message)
            .with_signature(signature.signature())
            .verify()
            .await?;
        
        assert!(verification.is_valid());
    }
    
    Ok(())
}

#[tokio::test]
async fn test_cross_algorithm_failure() -> Result<(), Box<dyn std::error::Error>> {
    // Generate ML-DSA-44 key pair
    let keypair_mldsa = SignatureBuilder::ml_dsa_44()
        .generate()
        .await?;
    
    // Try to use FALCON-512 with ML-DSA-44 public key
    let result = SignatureBuilder::falcon_512()
        .with_public_key(keypair_mldsa.public_key.ok_or("No public key")?);
    
    // This should fail due to wrong key size
    assert!(result.is_err());
    
    Ok(())
}

#[tokio::test]
async fn test_large_message_signature() -> Result<(), Box<dyn std::error::Error>> {
    let keypair = SignatureBuilder::ml_dsa_87()
        .generate()
        .await?;
    
    // Create a large message (1 MB)
    let large_message = vec![0x42u8; 1024 * 1024];
    
    // Sign large message
    let signature = keypair
        .with_message(&large_message)
        .sign()
        .await?;
    
    // Verify large message
    let verification = keypair
        .with_message(&large_message)
        .with_signature(signature.signature())
        .verify()
        .await?;
    
    assert!(verification.is_valid());
    
    Ok(())
}

#[tokio::test]
async fn test_empty_message_signature() -> Result<(), Box<dyn std::error::Error>> {
    let keypair = SignatureBuilder::falcon_512()
        .generate()
        .await?;
    
    // Sign empty message
    let signature = keypair
        .with_message(b"")
        .sign()
        .await?;
    
    // Verify empty message
    let verification = keypair
        .with_message(b"")
        .with_signature(signature.signature())
        .verify()
        .await?;
    
    assert!(verification.is_valid());
    
    Ok(())
}