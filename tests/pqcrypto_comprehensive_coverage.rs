//! Comprehensive test coverage for pqcrypto module edge cases and error conditions
//! This file fills in the gaps to achieve 100% test coverage

use cryypt::pqcrypto::{
    KemAlgorithm, SignatureAlgorithm, SharedSecret,
    api::{KemKeyPairBuilder, EncapsulateBuilder, DecapsulateBuilder, CiphertextBuilder,
          SignatureKeyPairBuilder, SignBuilder, VerifyBuilder, MessageBuilder, SignatureDataBuilder},
};
use cryypt::prelude::*;
use std::sync::Arc;

#[tokio::test]
async fn test_invalid_hex_encoding() -> Result<(), Box<dyn std::error::Error>> {
    // Invalid hex characters in KEM
    let result = KemBuilder::ml_kem_512().with_public_key_hex("invalid_hex_xyz123");
    assert!(result.is_err());
    
    let result = KemBuilder::ml_kem_768().with_secret_key_hex("not_valid_hex!@#");
    assert!(result.is_err());
    
    // Invalid hex characters in Signature
    let result = SignatureBuilder::ml_dsa_44().with_public_key_hex("gghhii"); // g,h,i not hex
    assert!(result.is_err());
    
    let result = SignatureBuilder::falcon_512().with_secret_key_hex("zzzyyy");
    assert!(result.is_err());
    
    // Wrong length hex for SharedSecret
    let result = SharedSecret::from_hex(KemAlgorithm::MlKem512, "deadbeef"); // too short
    assert!(result.is_err());
    
    let result = SharedSecret::from_hex(KemAlgorithm::MlKem768, "ab"); // way too short
    assert!(result.is_err());
    
    Ok(())
}

#[tokio::test]
async fn test_invalid_base64_encoding() -> Result<(), Box<dyn std::error::Error>> {
    // Invalid base64 in KEM
    let result = KemBuilder::ml_kem_1024().with_public_key_base64("invalid===base64");
    assert!(result.is_err());
    
    // Invalid base64 in Signature  
    let result = SignatureBuilder::ml_dsa_65().with_secret_key_base64("not*valid*base64");
    assert!(result.is_err());
    
    let result = SignatureBuilder::falcon_1024().with_message_base64("bad@base64");
    assert!(result.is_err());
    
    // Wrong length base64 for SharedSecret
    let result = SharedSecret::from_base64(KemAlgorithm::MlKem1024, "dGVzdA=="); // "test" = 4 bytes
    assert!(result.is_err());
    
    Ok(())
}

#[tokio::test]
async fn test_file_io_errors() -> Result<(), Box<dyn std::error::Error>> {
    // Non-existent files for KEM
    let result = KemBuilder::ml_kem_512()
        .with_keypair_files("/nonexistent/path/pk.key", "/nonexistent/path/sk.key")
        .await;
    assert!(result.is_err());
    
    // Non-existent files for Signature
    let result = SignatureBuilder::ml_dsa_87()
        .with_keypair_files("/fake/public.key", "/fake/secret.key")
        .await;
    assert!(result.is_err());
    
    let result = SignatureBuilder::falcon_512()
        .with_message_file("/nonexistent/message.txt")
        .await;
    assert!(result.is_err());
    
    let result = SignatureBuilder::ml_dsa_44()
        .with_signature_file("/missing/signature.bin")
        .await;
    assert!(result.is_err());
    
    Ok(())
}

#[tokio::test]
async fn test_algorithm_defaults_and_display() -> Result<(), Box<dyn std::error::Error>> {
    // Test Default implementations
    let default_kem = KemAlgorithm::default();
    assert_eq!(default_kem, KemAlgorithm::MlKem768);
    
    let default_sig = SignatureAlgorithm::default();
    assert_eq!(default_sig, SignatureAlgorithm::MlDsa65);
    
    // Test Display formatting
    assert_eq!(format!("{}", KemAlgorithm::MlKem512), "ML-KEM-512");
    assert_eq!(format!("{}", KemAlgorithm::MlKem768), "ML-KEM-768");
    assert_eq!(format!("{}", KemAlgorithm::MlKem1024), "ML-KEM-1024");
    
    assert_eq!(format!("{}", SignatureAlgorithm::MlDsa44), "ML-DSA-44");
    assert_eq!(format!("{}", SignatureAlgorithm::MlDsa65), "ML-DSA-65");
    assert_eq!(format!("{}", SignatureAlgorithm::MlDsa87), "ML-DSA-87");
    assert_eq!(format!("{}", SignatureAlgorithm::Falcon512), "FALCON-512");
    assert_eq!(format!("{}", SignatureAlgorithm::Falcon1024), "FALCON-1024");
    
    assert_eq!(format!("{}", SignatureAlgorithm::SphincsShaSha256_128fSimple), "SPHINCS+-SHA256-128f-simple");
    assert_eq!(format!("{}", SignatureAlgorithm::SphincsShaSha256_128sSimple), "SPHINCS+-SHA256-128s-simple");
    assert_eq!(format!("{}", SignatureAlgorithm::SphincsShaSha256_192fSimple), "SPHINCS+-SHA256-192f-simple");
    assert_eq!(format!("{}", SignatureAlgorithm::SphincsShaSha256_192sSimple), "SPHINCS+-SHA256-192s-simple");
    assert_eq!(format!("{}", SignatureAlgorithm::SphincsShaSha256_256fSimple), "SPHINCS+-SHA256-256f-simple");
    assert_eq!(format!("{}", SignatureAlgorithm::SphincsShaSha256_256sSimple), "SPHINCS+-SHA256-256s-simple");
    
    Ok(())
}

#[tokio::test]
async fn test_sphincs_individual_variants() -> Result<(), Box<dyn std::error::Error>> {
    let variants = vec![
        ("sha256-128f-simple", SignatureAlgorithm::SphincsShaSha256_128fSimple),
        ("sha256-128s-simple", SignatureAlgorithm::SphincsShaSha256_128sSimple),
        ("sha256-192f-simple", SignatureAlgorithm::SphincsShaSha256_192fSimple),
        ("sha256-192s-simple", SignatureAlgorithm::SphincsShaSha256_192sSimple),
        ("sha256-256f-simple", SignatureAlgorithm::SphincsShaSha256_256fSimple),
        ("sha256-256s-simple", SignatureAlgorithm::SphincsShaSha256_256sSimple),
    ];
    
    for (name, expected_alg) in variants {
        let keypair = SignatureBuilder::sphincs_plus(name)?.generate().await?;
        let pk = keypair.public_key_vec();
        let sk = keypair.secret_key_vec();
        
        let signature = SignatureBuilder::sphincs_plus(name)?
            .with_secret_key(sk)?
            .with_message(b"test message")
            .sign()
            .await?;
        
        assert_eq!(signature.algorithm(), expected_alg);
        
        let verification = SignatureBuilder::sphincs_plus(name)?
            .with_public_key(pk)?
            .with_message(b"test message")
            .with_signature(signature.signature())
            .verify()
            .await?;
        
        assert!(verification.is_valid());
    }
    
    // Test invalid SPHINCS+ variant
    let result = SignatureBuilder::sphincs_plus("invalid-variant");
    assert!(result.is_err());
    
    let result = SignatureBuilder::sphincs_plus("sha256-999x-invalid");
    assert!(result.is_err());
    
    Ok(())
}

#[tokio::test]
async fn test_shared_secret_methods() -> Result<(), Box<dyn std::error::Error>> {
    // Test all SharedSecret constructor and comparison methods
    let secret_bytes = vec![0xDEu8; 32];
    let secret1 = SharedSecret::new(KemAlgorithm::MlKem512, secret_bytes.clone());
    let secret2 = SharedSecret::new(KemAlgorithm::MlKem512, secret_bytes.clone());
    let secret3 = SharedSecret::new(KemAlgorithm::MlKem768, secret_bytes.clone());
    let secret4 = SharedSecret::new(KemAlgorithm::MlKem512, vec![0xABu8; 32]);
    
    // Test equality (constant time)
    assert_eq!(secret1, secret2);
    assert_ne!(secret1, secret3); // Different algorithms
    assert_ne!(secret1, secret4); // Different secret data
    
    // Test accessor methods
    assert_eq!(secret1.algorithm(), KemAlgorithm::MlKem512);
    assert_eq!(secret1.as_bytes(), &secret_bytes[..]);
    assert_eq!(secret1.size(), 32);
    
    // Test hex conversion round trip
    let hex_str = secret1.to_hex();
    let from_hex = SharedSecret::from_hex(KemAlgorithm::MlKem512, &hex_str)?;
    assert_eq!(secret1, from_hex);
    
    // Test base64 conversion round trip
    let b64_str = secret1.to_base64();
    let from_b64 = SharedSecret::from_base64(KemAlgorithm::MlKem512, &b64_str)?;
    assert_eq!(secret1, from_b64);
    
    // Test serialization round trip
    let json = serde_json::to_string(&secret1)?;
    let deserialized: SharedSecret = serde_json::from_str(&json)?;
    assert_eq!(secret1, deserialized);
    
    Ok(())
}

#[tokio::test]
async fn test_result_type_methods() -> Result<(), Box<dyn std::error::Error>> {
    // Test EncapsulationResult methods
    let keypair = KemBuilder::ml_kem_768().generate().await?;
    let pk = keypair.public_key_vec();
    
    let encap = KemBuilder::ml_kem_768()
        .with_public_key(pk)?
        .encapsulate()
        .await?;
    
    // Test all methods
    assert_eq!(encap.algorithm(), KemAlgorithm::MlKem768);
    assert_eq!(encap.ciphertext_size(), 1088);
    assert!(!encap.ciphertext_hex().is_empty());
    assert!(!encap.ciphertext_base64().is_empty());
    assert_eq!(encap.ciphertext(), encap.ciphertext_vec());
    assert_eq!(encap.shared_secret().size(), 32);
    
    // Test signature result methods
    let sig_keypair = SignatureBuilder::ml_dsa_65().generate().await?;
    let pk = sig_keypair.public_key_vec();
    let sk = sig_keypair.secret_key_vec();
    
    let signature = SignatureBuilder::ml_dsa_65()
        .with_secret_key(sk)?
        .with_message(b"test message")
        .sign()
        .await?;
    
    assert_eq!(signature.algorithm(), SignatureAlgorithm::MlDsa65);
    assert!(signature.signature_size() > 0);
    assert!(!signature.signature_hex().is_empty());
    assert!(!signature.signature_base64().is_empty());
    assert!(signature.is_detached());
    
    let verification = SignatureBuilder::ml_dsa_65()
        .with_public_key(pk)?
        .with_message(b"test message")
        .with_signature(signature.signature())
        .verify()
        .await?;
    
    assert!(verification.is_valid());
    
    let result = verification.to_result();
    assert!(result.is_ok());
    
    Ok(())
}

#[tokio::test]
async fn test_concurrent_operations() -> Result<(), Box<dyn std::error::Error>> {
    let keypair = Arc::new(KemBuilder::ml_kem_512().generate().await?);
    
    // Test concurrent encapsulation operations
    let tasks: Vec<_> = (0..5).map(|i| {
        let kp = keypair.clone();
        tokio::spawn(async move {
            let pk = kp.public_key_vec();
            let encap = KemBuilder::ml_kem_512()
                .with_public_key(pk)?
                .encapsulate()
                .await?;
            
            // Each should produce different ciphertext/shared secrets
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(encap.ciphertext_hex())
        })
    }).collect();
    
    let mut results = Vec::new();
    for task in tasks {
        let result = task.await??;
        results.push(result);
    }
    
    // All ciphertexts should be different (randomized)
    for i in 0..results.len() {
        for j in i+1..results.len() {
            assert_ne!(results[i], results[j], "Concurrent operations should produce different ciphertexts");
        }
    }
    
    Ok(())
}

#[tokio::test]
async fn test_signature_concurrent_operations() -> Result<(), Box<dyn std::error::Error>> {
    let keypair = Arc::new(SignatureBuilder::falcon_512().generate().await?);
    
    // Test concurrent signing operations
    let tasks: Vec<_> = (0..5).map(|i| {
        let kp = keypair.clone();
        tokio::spawn(async move {
            let sk = kp.secret_key_vec();
            let message = format!("Message {}", i);
            let signature = SignatureBuilder::falcon_512()
                .with_secret_key(sk)?
                .with_message(message.as_bytes())
                .sign()
                .await?;
            
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(signature.signature_hex())
        })
    }).collect();
    
    let mut results = Vec::new();
    for task in tasks {
        let result = task.await??;
        results.push(result);
    }
    
    // All signatures should be different (different messages)
    for i in 0..results.len() {
        for j in i+1..results.len() {
            assert_ne!(results[i], results[j], "Signatures of different messages should be different");
        }
    }
    
    Ok(())
}

#[test]
fn test_malformed_serialization() {
    // Invalid JSON structure for SharedSecret
    let invalid_json = r#"{"algorithm": "invalid-alg", "secret": "invalid"}"#;
    let result: Result<SharedSecret, _> = serde_json::from_str(invalid_json);
    assert!(result.is_err());
    
    // Wrong shared secret size in JSON
    let invalid_secret = r#"{"algorithm": "ML-KEM-768", "secret": "dGVzdA=="}"#; // "test" = 4 bytes, need 32
    let result: Result<SharedSecret, _> = serde_json::from_str(invalid_secret);
    assert!(result.is_err());
    
    // Completely malformed JSON
    let malformed = "not json at all";
    let result: Result<SharedSecret, _> = serde_json::from_str(malformed);
    assert!(result.is_err());
}

#[tokio::test]
async fn test_algorithm_edge_cases() -> Result<(), Box<dyn std::error::Error>> {
    // Test algorithm security level methods
    assert_eq!(KemAlgorithm::MlKem512.security_level(), 1);
    assert_eq!(KemAlgorithm::MlKem768.security_level(), 3);
    assert_eq!(KemAlgorithm::MlKem1024.security_level(), 5);
    
    assert_eq!(SignatureAlgorithm::MlDsa44.security_level(), 2);
    assert_eq!(SignatureAlgorithm::MlDsa65.security_level(), 3);
    assert_eq!(SignatureAlgorithm::MlDsa87.security_level(), 5);
    
    assert_eq!(SignatureAlgorithm::Falcon512.security_level(), 1);
    assert_eq!(SignatureAlgorithm::Falcon1024.security_level(), 5);
    
    // Test SPHINCS+ variant methods
    assert!(SignatureAlgorithm::SphincsShaSha256_128fSimple.is_fast_variant());
    assert!(!SignatureAlgorithm::SphincsShaSha256_128fSimple.is_small_variant());
    
    assert!(!SignatureAlgorithm::SphincsShaSha256_128sSimple.is_fast_variant());
    assert!(SignatureAlgorithm::SphincsShaSha256_128sSimple.is_small_variant());
    
    // Test invalid algorithm construction
    let result = KemBuilder::ml_kem(999);
    assert!(result.is_err());
    
    let result = SignatureBuilder::ml_dsa(999);
    assert!(result.is_err());
    
    let result = SignatureBuilder::falcon(999);
    assert!(result.is_err());
    
    Ok(())
}

#[tokio::test]
async fn test_memory_intensive_operations() -> Result<(), Box<dyn std::error::Error>> {
    // Test with large message (10 MB)
    let large_message = vec![0x42u8; 10 * 1024 * 1024];
    
    let keypair = SignatureBuilder::ml_dsa_87().generate().await?;
    let pk = keypair.public_key_vec();
    let sk = keypair.secret_key_vec();
    
    let signature = SignatureBuilder::ml_dsa_87()
        .with_secret_key(sk)?
        .with_message(large_message.clone())
        .sign()
        .await?;
    
    let verification = SignatureBuilder::ml_dsa_87()
        .with_public_key(pk)?
        .with_message(large_message)
        .with_signature(signature.signature())
        .verify()
        .await?;
    
    assert!(verification.is_valid());
    
    Ok(())
}

#[tokio::test]
async fn test_empty_and_single_byte_messages() -> Result<(), Box<dyn std::error::Error>> {
    let keypair = SignatureBuilder::ml_dsa_44().generate().await?;
    let pk = keypair.public_key_vec();
    let sk = keypair.secret_key_vec();
    
    // Test empty message
    let signature = SignatureBuilder::ml_dsa_44()
        .with_secret_key(sk.clone())?
        .with_message(b"")
        .sign()
        .await?;
    
    let verification = SignatureBuilder::ml_dsa_44()
        .with_public_key(pk.clone())?
        .with_message(b"")
        .with_signature(signature.signature())
        .verify()
        .await?;
    
    assert!(verification.is_valid());
    
    // Test single byte message
    let signature = SignatureBuilder::ml_dsa_44()
        .with_secret_key(sk)?
        .with_message(b"A")
        .sign()
        .await?;
    
    let verification = SignatureBuilder::ml_dsa_44()
        .with_public_key(pk)?
        .with_message(b"A")
        .with_signature(signature.signature())
        .verify()
        .await?;
    
    assert!(verification.is_valid());
    
    Ok(())
}

#[tokio::test]
async fn test_verification_result_error_conversion() -> Result<(), Box<dyn std::error::Error>> {
    let keypair = SignatureBuilder::falcon_1024().generate().await?;
    let pk = keypair.public_key_vec();
    let sk = keypair.secret_key_vec();
    
    let signature = SignatureBuilder::falcon_1024()
        .with_secret_key(sk)?
        .with_message(b"original message")
        .sign()
        .await?;
    
    // Test valid verification to_result
    let verification = SignatureBuilder::falcon_1024()
        .with_public_key(pk.clone())?
        .with_message(b"original message")
        .with_signature(signature.signature())
        .verify()
        .await?;
    
    let result = verification.to_result();
    assert!(result.is_ok());
    
    // Test invalid verification to_result
    let invalid_verification = SignatureBuilder::falcon_1024()
        .with_public_key(pk)?
        .with_message(b"tampered message")
        .with_signature(signature.signature())
        .verify()
        .await?;
    
    let result = invalid_verification.to_result();
    assert!(result.is_err());
    assert!(matches!(result, Err(CryptError::AuthenticationFailed(_))));
    
    Ok(())
}