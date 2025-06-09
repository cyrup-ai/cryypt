//! Comprehensive Post-Quantum Cryptography Example
//!
//! This example demonstrates all features of the pqcrypto module:
//! - Key Encapsulation Mechanisms (ML-KEM)
//! - Digital Signatures (ML-DSA, FALCON, SPHINCS+)
//! - Hybrid encryption patterns
//! - Key serialization and storage
//! - Error handling
//! - Performance testing

use cryypt::cipher::api::builder_traits::CiphertextBuilder as CipherCiphertextBuilder;
use cryypt::pqcrypto::{
    CiphertextBuilder, DecapsulateBuilder, EncapsulateBuilder, KemKeyPairBuilder, MessageBuilder,
    SignBuilder, SignatureDataBuilder, SignatureKeyPairBuilder, VerifyBuilder,
};
use cryypt::prelude::*;
use std::time::Instant;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔐 Post-Quantum Cryptography Comprehensive Example");
    println!("==================================================\n");

    // 1. Key Encapsulation Mechanisms (KEM)
    kem_examples().await?;

    // 2. Digital Signatures
    signature_examples().await?;

    // 3. Hybrid Encryption
    hybrid_encryption_example().await?;

    // 4. Key Management and Persistence
    key_management_example().await?;

    // 5. Performance Comparison
    performance_comparison().await?;

    // 6. Error Handling
    error_handling_examples().await?;

    println!("\n🎉 All post-quantum cryptography examples completed successfully!");
    Ok(())
}

/// Demonstrate all KEM algorithms
async fn kem_examples() -> Result<(), Box<dyn std::error::Error>> {
    println!("1. 🔑 Key Encapsulation Mechanisms (KEM)");
    println!("----------------------------------------");

    // Test all ML-KEM variants
    for (name, builder) in [
        ("ML-KEM-512", KemBuilder::ml_kem_512()),
        ("ML-KEM-768", KemBuilder::ml_kem_768()),
        ("ML-KEM-1024", KemBuilder::ml_kem_1024()),
    ] {
        println!("\n📋 Testing {}", name);

        // Generate key pair
        let keypair = builder.generate().await?;
        let pk = keypair.public_key_vec();
        let sk = keypair.secret_key_vec();

        println!("  ✓ Key pair generated");
        println!("    - Public key: {} bytes", pk.len());
        println!("    - Secret key: {} bytes", sk.len());

        // Alice encapsulates
        let encapsulation = match name {
            "ML-KEM-512" => KemBuilder::ml_kem_512(),
            "ML-KEM-768" => KemBuilder::ml_kem_768(),
            "ML-KEM-1024" => KemBuilder::ml_kem_1024(),
            _ => unreachable!(),
        }
        .with_public_key(pk)?
        .encapsulate()
        .await?;

        println!("  ✓ Encapsulation successful");
        println!(
            "    - Shared secret: {} bytes",
            encapsulation.shared_secret().as_bytes().len()
        );
        println!(
            "    - Ciphertext: {} bytes",
            encapsulation.ciphertext_size()
        );

        // Bob decapsulates
        let builder_with_sk = match name {
            "ML-KEM-512" => KemBuilder::ml_kem_512(),
            "ML-KEM-768" => KemBuilder::ml_kem_768(),
            "ML-KEM-1024" => KemBuilder::ml_kem_1024(),
            _ => unreachable!(),
        }
        .with_secret_key(sk)?;

        let decapsulation = builder_with_sk
            .with_ciphertext(encapsulation.ciphertext())
            .decapsulate()
            .await?;

        // Verify shared secrets match
        assert_eq!(
            encapsulation.shared_secret().as_bytes(),
            decapsulation.shared_secret().as_bytes()
        );
        println!("  ✓ Shared secrets match");
    }

    Ok(())
}

/// Demonstrate all signature algorithms
async fn signature_examples() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n\n2. ✍️  Digital Signatures");
    println!("-------------------------");

    let message = b"Critical security update: Post-quantum cryptography is now active!";

    // ML-DSA variants
    for (name, builder) in [
        ("ML-DSA-44", SignatureBuilder::ml_dsa_44()),
        ("ML-DSA-65", SignatureBuilder::ml_dsa_65()),
        ("ML-DSA-87", SignatureBuilder::ml_dsa_87()),
    ] {
        println!("\n📋 Testing {}", name);

        let keypair = builder.generate().await?;
        let pk = keypair.public_key_vec();
        let sk = keypair.secret_key_vec();

        let signature = match name {
            "ML-DSA-44" => SignatureBuilder::ml_dsa_44(),
            "ML-DSA-65" => SignatureBuilder::ml_dsa_65(),
            "ML-DSA-87" => SignatureBuilder::ml_dsa_87(),
            _ => unreachable!(),
        }
        .with_secret_key(sk)?
        .with_message(message)
        .sign()
        .await?;

        let verification = match name {
            "ML-DSA-44" => SignatureBuilder::ml_dsa_44(),
            "ML-DSA-65" => SignatureBuilder::ml_dsa_65(),
            "ML-DSA-87" => SignatureBuilder::ml_dsa_87(),
            _ => unreachable!(),
        }
        .with_public_key(pk)?
        .with_message(message)
        .with_signature(signature.signature())
        .verify()
        .await?;

        assert!(verification.is_valid());
        println!("  ✓ Signature verified");
        println!("    - Signature size: {} bytes", signature.signature_size());
    }

    // FALCON variants
    for (name, builder) in [
        ("FALCON-512", SignatureBuilder::falcon_512()),
        ("FALCON-1024", SignatureBuilder::falcon_1024()),
    ] {
        println!("\n📋 Testing {}", name);

        let keypair = builder.generate().await?;
        let pk = keypair.public_key_vec();
        let sk = keypair.secret_key_vec();

        let signature = match name {
            "FALCON-512" => SignatureBuilder::falcon_512(),
            "FALCON-1024" => SignatureBuilder::falcon_1024(),
            _ => unreachable!(),
        }
        .with_secret_key(sk)?
        .with_message(message)
        .sign()
        .await?;

        let builder_with_pk = match name {
            "FALCON-512" => SignatureBuilder::falcon_512(),
            "FALCON-1024" => SignatureBuilder::falcon_1024(),
            _ => unreachable!(),
        }
        .with_public_key(pk)?;

        let verification = builder_with_pk
            .with_message(message)
            .with_signature(signature.signature())
            .verify()
            .await?;

        assert!(verification.is_valid());
        println!(
            "  ✓ Signature verified (compact: {} bytes)",
            signature.signature_size()
        );
    }

    // SPHINCS+ variants
    let sphincs_variants = [
        "sha256-128f-simple",
        "sha256-128s-simple",
        "sha256-192f-simple",
        "sha256-192s-simple",
        "sha256-256f-simple",
        "sha256-256s-simple",
    ];

    for variant in &sphincs_variants[..2] {
        // Test first 2 for brevity
        println!("\n📋 Testing SPHINCS+ {}", variant);

        let keypair = SignatureBuilder::sphincs_plus(variant)?.generate().await?;
        let pk = keypair.public_key_vec();
        let sk = keypair.secret_key_vec();

        let signature = SignatureBuilder::sphincs_plus(variant)?
            .with_secret_key(sk)?
            .with_message(message)
            .sign()
            .await?;

        let verification = SignatureBuilder::sphincs_plus(variant)?
            .with_public_key(pk)?
            .with_message(message)
            .with_signature(signature.signature())
            .verify()
            .await?;

        assert!(verification.is_valid());
        println!("  ✓ Signature verified");
    }

    Ok(())
}

/// Demonstrate hybrid encryption combining KEM + AES
async fn hybrid_encryption_example() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n\n3. 🔐 Hybrid Encryption (KEM + AES)");
    println!("-----------------------------------");

    // Large message to encrypt
    let plaintext =
        "This is a confidential document that needs post-quantum protection. ".repeat(50);
    println!("📄 Message size: {} bytes", plaintext.len());

    // Step 1: Generate KEM key pair
    let kem_keypair = KemBuilder::ml_kem_768().generate().await?;
    let pk = kem_keypair.public_key_vec();
    let sk = kem_keypair.secret_key_vec();

    // Step 2: Encapsulate to get shared secret
    let encapsulation = KemBuilder::ml_kem_768()
        .with_public_key(pk)?
        .encapsulate()
        .await?;

    // Step 3: Use shared secret as AES key
    let aes_ciphertext = Cipher::aes()
        .with_key(Key::from_bytes(
            encapsulation.shared_secret().as_bytes().to_vec(),
        ))
        .with_data(plaintext.as_bytes())
        .encrypt()
        .await?;

    // Store the ciphertext bytes before printing
    let aes_ciphertext_bytes = aes_ciphertext.to_bytes();

    println!("🔒 Encryption successful");
    println!(
        "  - KEM ciphertext: {} bytes",
        encapsulation.ciphertext_size()
    );
    println!("  - AES ciphertext: {} bytes", aes_ciphertext_bytes.len());

    // Step 4: Decapsulate to recover shared secret
    let decapsulation = KemBuilder::ml_kem_768()
        .with_secret_key(sk)?
        .with_ciphertext(encapsulation.ciphertext())
        .decapsulate()
        .await?;

    // Step 5: Decrypt using recovered shared secret
    let decrypted_bytes = Cipher::aes()
        .with_key(Key::from_bytes(
            decapsulation.shared_secret().as_bytes().to_vec(),
        ))
        .with_ciphertext(aes_ciphertext_bytes)
        .decrypt()
        .await?;

    let decrypted_text = String::from_utf8(decrypted_bytes)?;

    assert_eq!(plaintext, decrypted_text);
    println!("🔓 Decryption successful - messages match!");

    Ok(())
}

/// Demonstrate key serialization and file operations
async fn key_management_example() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n\n4. 💾 Key Management and Persistence");
    println!("------------------------------------");

    let temp_dir = "/tmp/pqcrypto_keys";
    std::fs::create_dir_all(temp_dir).ok();

    // Generate keys
    let kem_keypair = KemBuilder::ml_kem_512().generate().await?;
    let sig_keypair = SignatureBuilder::ml_dsa_44().generate().await?;

    // Save KEM keys as binary
    let kem_pk_path = format!("{}/kem_public.key", temp_dir);
    let kem_sk_path = format!("{}/kem_secret.key", temp_dir);

    tokio::fs::write(&kem_pk_path, kem_keypair.public_key()).await?;
    tokio::fs::write(&kem_sk_path, kem_keypair.secret_key()).await?;
    println!("💾 KEM keys saved to disk");

    // Save signature keys as hex
    let sig_pk_hex = hex::encode(sig_keypair.public_key());
    let sig_sk_hex = hex::encode(sig_keypair.secret_key());

    let sig_pk_path = format!("{}/sig_public.hex", temp_dir);
    let sig_sk_path = format!("{}/sig_secret.hex", temp_dir);

    tokio::fs::write(&sig_pk_path, &sig_pk_hex).await?;
    tokio::fs::write(&sig_sk_path, &sig_sk_hex).await?;
    println!("💾 Signature keys saved as hex");

    // Load and verify keys work
    let loaded_kem_pk = tokio::fs::read(&kem_pk_path).await?;
    let loaded_kem_sk = tokio::fs::read(&kem_sk_path).await?;

    let encap = KemBuilder::ml_kem_512()
        .with_public_key(loaded_kem_pk)?
        .encapsulate()
        .await?;

    let decap = KemBuilder::ml_kem_512()
        .with_secret_key(loaded_kem_sk)?
        .with_ciphertext(encap.ciphertext())
        .decapsulate()
        .await?;

    assert_eq!(
        encap.shared_secret().as_bytes(),
        decap.shared_secret().as_bytes()
    );
    println!("✅ Loaded KEM keys work correctly");

    // Load signature keys from hex
    let loaded_sig_pk_hex = tokio::fs::read_to_string(&sig_pk_path).await?;
    let loaded_sig_sk_hex = tokio::fs::read_to_string(&sig_sk_path).await?;

    let message = b"Test message for loaded keys";
    let signature = SignatureBuilder::ml_dsa_44()
        .with_secret_key_hex(&loaded_sig_sk_hex)?
        .with_message(message)
        .sign()
        .await?;

    let verification = SignatureBuilder::ml_dsa_44()
        .with_public_key_hex(&loaded_sig_pk_hex)?
        .with_message(message)
        .with_signature(signature.signature())
        .verify()
        .await?;

    assert!(verification.is_valid());
    println!("✅ Loaded signature keys work correctly");

    // Cleanup
    std::fs::remove_dir_all(temp_dir).ok();

    Ok(())
}

/// Compare performance across algorithms
async fn performance_comparison() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n\n5. ⚡ Performance Comparison");
    println!("---------------------------");

    // KEM Performance
    println!("\n🏃 KEM Algorithm Performance:");
    for (name, builder) in [
        ("ML-KEM-512", KemBuilder::ml_kem_512()),
        ("ML-KEM-768", KemBuilder::ml_kem_768()),
        ("ML-KEM-1024", KemBuilder::ml_kem_1024()),
    ] {
        let start = Instant::now();
        let keypair = builder.generate().await?;
        let keygen_time = start.elapsed();

        let pk = keypair.public_key_vec();
        let sk = keypair.secret_key_vec();

        let start = Instant::now();
        let encap = match name {
            "ML-KEM-512" => KemBuilder::ml_kem_512(),
            "ML-KEM-768" => KemBuilder::ml_kem_768(),
            "ML-KEM-1024" => KemBuilder::ml_kem_1024(),
            _ => unreachable!(),
        }
        .with_public_key(pk)?
        .encapsulate()
        .await?;
        let encap_time = start.elapsed();

        let start = Instant::now();
        let _decap = match name {
            "ML-KEM-512" => KemBuilder::ml_kem_512(),
            "ML-KEM-768" => KemBuilder::ml_kem_768(),
            "ML-KEM-1024" => KemBuilder::ml_kem_1024(),
            _ => unreachable!(),
        }
        .with_secret_key(sk)?
        .with_ciphertext(encap.ciphertext())
        .decapsulate()
        .await?;
        let decap_time = start.elapsed();

        println!(
            "  {} - KeyGen: {:?}, Encaps: {:?}, Decaps: {:?}",
            name, keygen_time, encap_time, decap_time
        );
    }

    // Signature Performance
    println!("\n✍️  Signature Algorithm Performance:");
    let test_message = b"Performance test message";

    // Test ML-DSA performance
    {
        let name = "ML-DSA-44";
        let builder = SignatureBuilder::ml_dsa_44();
        let start = Instant::now();
        let keypair = builder.generate().await?;
        let keygen_time = start.elapsed();

        let pk = keypair.public_key_vec();
        let sk = keypair.secret_key_vec();

        let start = Instant::now();
        let signature = SignatureBuilder::ml_dsa_44()
            .with_secret_key(sk)?
            .with_message(test_message)
            .sign()
            .await?;
        let sign_time = start.elapsed();

        let start = Instant::now();
        let _verification = SignatureBuilder::ml_dsa_44()
            .with_public_key(pk)?
            .with_message(test_message)
            .with_signature(signature.signature())
            .verify()
            .await?;
        let verify_time = start.elapsed();

        println!(
            "  {} - KeyGen: {:?}, Sign: {:?}, Verify: {:?}, Size: {} bytes",
            name,
            keygen_time,
            sign_time,
            verify_time,
            signature.signature_size()
        );
    }

    // Test FALCON performance
    {
        let name = "FALCON-512";
        let builder = SignatureBuilder::falcon_512();
        let start = Instant::now();
        let keypair = builder.generate().await?;
        let keygen_time = start.elapsed();

        let pk = keypair.public_key_vec();
        let sk = keypair.secret_key_vec();

        let start = Instant::now();
        let signature = SignatureBuilder::falcon_512()
            .with_secret_key(sk)?
            .with_message(test_message)
            .sign()
            .await?;
        let sign_time = start.elapsed();

        let start = Instant::now();
        let _verification = SignatureBuilder::falcon_512()
            .with_public_key(pk)?
            .with_message(test_message)
            .with_signature(signature.signature())
            .verify()
            .await?;
        let verify_time = start.elapsed();

        println!(
            "  {} - KeyGen: {:?}, Sign: {:?}, Verify: {:?}, Size: {} bytes",
            name,
            keygen_time,
            sign_time,
            verify_time,
            signature.signature_size()
        );
    }

    Ok(())
}

/// Demonstrate proper error handling
async fn error_handling_examples() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n\n6. ⚠️  Error Handling Examples");
    println!("------------------------------");

    // Invalid key size
    println!("\n🔍 Testing invalid key sizes:");
    let invalid_key = vec![0u8; 100];

    match KemBuilder::ml_kem_512().with_public_key(invalid_key) {
        Err(CryptError::InvalidKeySize { expected, actual }) => {
            println!(
                "  ✓ Correctly caught invalid KEM key size: expected {}, got {}",
                expected, actual
            );
        }
        _ => panic!("Should have caught invalid key size"),
    }

    match SignatureBuilder::ml_dsa_44().with_public_key(vec![0u8; 50]) {
        Err(CryptError::InvalidKeySize { expected, actual }) => {
            println!(
                "  ✓ Correctly caught invalid signature key size: expected {}, got {}",
                expected, actual
            );
        }
        _ => panic!("Should have caught invalid signature key size"),
    }

    // Invalid algorithm parameters
    println!("\n🔍 Testing invalid algorithm parameters:");
    match KemBuilder::ml_kem(999) {
        Err(CryptError::UnsupportedAlgorithm(msg)) => {
            println!("  ✓ Correctly caught unsupported algorithm: {}", msg);
        }
        _ => panic!("Should have caught unsupported algorithm"),
    }

    // Signature verification failure
    println!("\n🔍 Testing signature verification failure:");
    let keypair = SignatureBuilder::falcon_512().generate().await?;
    let pk = keypair.public_key_vec();
    let sk = keypair.secret_key_vec();

    let signature = SignatureBuilder::falcon_512()
        .with_secret_key(sk)?
        .with_message(b"original message")
        .sign()
        .await?;

    let verification = SignatureBuilder::falcon_512()
        .with_public_key(pk)?
        .with_message(b"tampered message")
        .with_signature(signature.signature())
        .verify()
        .await?;

    match verification.to_result() {
        Err(CryptError::AuthenticationFailed(_)) => {
            println!("  ✓ Correctly detected tampered message");
        }
        _ => panic!("Should have detected authentication failure"),
    }

    println!("\n✅ All error handling tests passed");

    Ok(())
}
