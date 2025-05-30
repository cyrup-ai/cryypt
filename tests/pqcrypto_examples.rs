//! Comprehensive examples of post-quantum cryptography usage

use cryypt::pqcrypto::{
    KemAlgorithm, SignatureAlgorithm,
    api::{KemKeyPairBuilder, EncapsulateBuilder, DecapsulateBuilder, CiphertextBuilder,
          SignatureKeyPairBuilder, SignBuilder, VerifyBuilder, MessageBuilder, SignatureDataBuilder},
};
use cryypt::prelude::*;

/// Example: Basic KEM key exchange between Alice and Bob
#[tokio::test]
async fn example_basic_kem_key_exchange() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Basic KEM Key Exchange Example ===");

    // Bob generates a key pair
    println!("Bob generates ML-KEM-768 key pair...");
    let bob_keypair = KemBuilder::ml_kem_768().generate().await?;

    // Bob shares his public key with Alice
    let bob_public_key = bob_keypair.public_key_vec();
    let bob_secret_key = bob_keypair.secret_key_vec();
    println!(
        "Bob shares his public key (size: {} bytes)",
        bob_public_key.len()
    );

    // Alice encapsulates a shared secret using Bob's public key
    println!("\nAlice encapsulates shared secret...");
    let alice_encapsulation = KemBuilder::ml_kem_768()
        .with_public_key(bob_public_key)?
        .encapsulate()
        .await?;

    println!(
        "Alice's shared secret: {}",
        alice_encapsulation.shared_secret().to_hex()
    );
    println!(
        "Ciphertext size: {} bytes",
        alice_encapsulation.ciphertext_size()
    );

    // Alice sends the ciphertext to Bob
    let ciphertext = alice_encapsulation.ciphertext_vec();

    // Bob decapsulates to get the same shared secret
    println!("\nBob decapsulates shared secret...");
    let bob_decapsulation = KemBuilder::ml_kem_768()
        .with_secret_key(bob_secret_key)?
        .with_ciphertext(ciphertext)
        .decapsulate()
        .await?;

    println!(
        "Bob's shared secret: {}",
        bob_decapsulation.shared_secret().to_hex()
    );

    // Verify they have the same shared secret
    assert_eq!(
        alice_encapsulation.shared_secret().as_bytes(),
        bob_decapsulation.shared_secret().as_bytes()
    );
    println!("\n✓ Shared secrets match!");

    Ok(())
}

/// Example: Hybrid encryption using KEM + AES
#[tokio::test]
async fn example_hybrid_encryption() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Hybrid Encryption Example (KEM + AES) ===");

    // Generate KEM key pair
    let kem_keypair = KemBuilder::ml_kem_512().generate().await?;
    let pk = kem_keypair.public_key_vec();
    let sk = kem_keypair.secret_key_vec();

    // Message to encrypt
    let message = b"Secret message encrypted with post-quantum hybrid encryption";
    println!("Original message: {:?}", std::str::from_utf8(message)?);

    // --- Encryption (Sender) ---
    println!("\n--- Sender encrypts ---");

    // 1. Encapsulate to get shared secret
    let encapsulation = KemBuilder::ml_kem_512()
        .with_public_key(pk)?
        .encapsulate()
        .await?;

    // 2. Use shared secret as AES key
    let shared_secret = encapsulation.shared_secret().as_bytes();
    let aes_ciphertext = Cipher::aes()
        .with_key(Key::from_bytes(shared_secret.to_vec()))
        .with_data(message)
        .encrypt()
        .await?;

    println!(
        "KEM ciphertext size: {} bytes",
        encapsulation.ciphertext_size()
    );
    println!(
        "AES ciphertext size: {} bytes",
        aes_ciphertext.to_bytes().len()
    );

    // --- Decryption (Receiver) ---
    println!("\n--- Receiver decrypts ---");

    // 1. Decapsulate to recover shared secret
    let decapsulation = KemBuilder::ml_kem_512()
        .with_secret_key(sk)?
        .with_ciphertext(encapsulation.ciphertext())
        .decapsulate()
        .await?;

    // 2. Use shared secret as AES key to decrypt
    let decrypted_message: Vec<u8> = Cipher::aes()
        .with_key(Key::from_bytes(decapsulation.shared_secret().as_bytes().to_vec()))
        .with_ciphertext(aes_ciphertext.to_bytes())
        .decrypt()
        .await?;

    println!(
        "Decrypted message: {:?}",
        std::str::from_utf8(&decrypted_message)?
    );

    assert_eq!(message, &decrypted_message[..]);
    println!("\n✓ Message successfully decrypted!");

    Ok(())
}

/// Example: Digital signature for document signing
#[tokio::test]
async fn example_document_signing() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Document Signing Example ===");

    // Generate signing key pair
    println!("Generating ML-DSA-65 key pair...");
    let signing_keypair = SignatureBuilder::ml_dsa_65().generate().await?;
    let pk = signing_keypair.public_key_vec();
    let sk = signing_keypair.secret_key_vec();

    // Document to sign
    let document = r#"
    CONTRACT AGREEMENT
    
    This agreement is made between Party A and Party B.
    Date: 2024-01-15
    Amount: $10,000
    
    Terms and conditions apply.
    "#;

    println!("Document to sign:\n{}", document);

    // Sign the document
    println!("\nSigning document...");
    let signature = SignatureBuilder::ml_dsa_65()
        .with_secret_key(sk)?
        .with_message_text(document)
        .sign()
        .await?;

    println!("Signature size: {} bytes", signature.signature_size());
    println!("Signature (hex): {}", &signature.signature_hex()[..64]);
    println!("... (truncated)");

    // Verify the signature
    println!("\nVerifying signature...");
    let verification = SignatureBuilder::ml_dsa_65()
        .with_public_key(pk.clone())?
        .with_message_text(document)
        .with_signature(signature.signature())
        .verify()
        .await?;

    if verification.is_valid() {
        println!("✓ Signature is VALID");
    } else {
        println!("✗ Signature is INVALID");
    }

    // Try to verify with tampered document
    println!("\nVerifying with tampered document...");
    let tampered_document = document.replace("$10,000", "$100,000");

    let tampered_verification = SignatureBuilder::ml_dsa_65()
        .with_public_key(pk)?
        .with_message_text(&tampered_document)
        .with_signature(signature.signature())
        .verify()
        .await?;

    if !tampered_verification.is_valid() {
        println!("✓ Correctly rejected tampered document");
    }

    Ok(())
}

/// Example: Performance comparison of different algorithms
#[tokio::test]
async fn example_algorithm_comparison() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Algorithm Performance Comparison ===");

    use std::time::Instant;

    // Compare KEM algorithms
    println!("\n--- KEM Algorithms ---");

    for algorithm in [
        KemAlgorithm::MlKem512,
        KemAlgorithm::MlKem768,
        KemAlgorithm::MlKem1024,
    ] {
        println!(
            "\n{} (Security Level {})",
            algorithm,
            algorithm.security_level()
        );
        println!("  Public key: {} bytes", algorithm.public_key_size());
        println!("  Secret key: {} bytes", algorithm.secret_key_size());
        println!("  Ciphertext: {} bytes", algorithm.ciphertext_size());

        // Time key generation
        let start = Instant::now();
        let keypair = match algorithm {
            KemAlgorithm::MlKem512 => KemBuilder::ml_kem_512().generate().await?,
            KemAlgorithm::MlKem768 => KemBuilder::ml_kem_768().generate().await?,
            KemAlgorithm::MlKem1024 => KemBuilder::ml_kem_1024().generate().await?,
        };
        let keygen_time = start.elapsed();
        let pk = keypair.public_key_vec();
        let sk = keypair.secret_key_vec();

        // Time encapsulation
        let start = Instant::now();
        let encap = match algorithm {
            KemAlgorithm::MlKem512 => KemBuilder::ml_kem_512()
                .with_public_key(pk)?
                .encapsulate()
                .await?,
            KemAlgorithm::MlKem768 => KemBuilder::ml_kem_768()
                .with_public_key(pk)?
                .encapsulate()
                .await?,
            KemAlgorithm::MlKem1024 => KemBuilder::ml_kem_1024()
                .with_public_key(pk)?
                .encapsulate()
                .await?,
        };
        let encap_time = start.elapsed();

        // Time decapsulation
        let start = Instant::now();
        let _decap = match algorithm {
            KemAlgorithm::MlKem512 => KemBuilder::ml_kem_512()
                .with_secret_key(sk)?
                .with_ciphertext(encap.ciphertext())
                .decapsulate()
                .await?,
            KemAlgorithm::MlKem768 => KemBuilder::ml_kem_768()
                .with_secret_key(sk)?
                .with_ciphertext(encap.ciphertext())
                .decapsulate()
                .await?,
            KemAlgorithm::MlKem1024 => KemBuilder::ml_kem_1024()
                .with_secret_key(sk)?
                .with_ciphertext(encap.ciphertext())
                .decapsulate()
                .await?,
        };
        let decap_time = start.elapsed();

        println!("  KeyGen: {:?}", keygen_time);
        println!("  Encaps: {:?}", encap_time);
        println!("  Decaps: {:?}", decap_time);
    }

    // Compare signature algorithms
    println!("\n--- Signature Algorithms ---");

    let test_message = b"Performance test message";

    // ML-DSA
    for (name, builder) in [
        ("ML-DSA-44", SignatureBuilder::ml_dsa_44()),
        ("ML-DSA-65", SignatureBuilder::ml_dsa_65()),
        ("ML-DSA-87", SignatureBuilder::ml_dsa_87()),
    ] {
        println!("\n{}", name);

        let start = Instant::now();
        let keypair = builder.generate().await?;
        let keygen_time = start.elapsed();
        let pk = keypair.public_key_vec();
        let sk = keypair.secret_key_vec();

        let start = Instant::now();
        let sig = match name {
            "ML-DSA-44" => SignatureBuilder::ml_dsa_44()
                .with_secret_key(sk)?
                .with_message(test_message)
                .sign()
                .await?,
            "ML-DSA-65" => SignatureBuilder::ml_dsa_65()
                .with_secret_key(sk)?
                .with_message(test_message)
                .sign()
                .await?,
            "ML-DSA-87" => SignatureBuilder::ml_dsa_87()
                .with_secret_key(sk)?
                .with_message(test_message)
                .sign()
                .await?,
            _ => panic!("Unknown algorithm"),
        };
        let sign_time = start.elapsed();

        let start = Instant::now();
        let _verify = match name {
            "ML-DSA-44" => SignatureBuilder::ml_dsa_44()
                .with_public_key(pk)?
                .with_message(test_message)
                .with_signature(sig.signature())
                .verify()
                .await?,
            "ML-DSA-65" => SignatureBuilder::ml_dsa_65()
                .with_public_key(pk)?
                .with_message(test_message)
                .with_signature(sig.signature())
                .verify()
                .await?,
            "ML-DSA-87" => SignatureBuilder::ml_dsa_87()
                .with_public_key(pk)?
                .with_message(test_message)
                .with_signature(sig.signature())
                .verify()
                .await?,
            _ => panic!("Unknown algorithm"),
        };
        let verify_time = start.elapsed();

        println!("  Signature: {} bytes", sig.signature_size());
        println!("  KeyGen: {:?}", keygen_time);
        println!("  Sign: {:?}", sign_time);
        println!("  Verify: {:?}", verify_time);
    }

    // FALCON (typically faster)
    println!("\nFALCON-512");
    let start = Instant::now();
    let falcon_kp = SignatureBuilder::falcon_512().generate().await?;
    let keygen_time = start.elapsed();
    let pk = falcon_kp.public_key_vec();
    let sk = falcon_kp.secret_key_vec();

    let start = Instant::now();
    let sig = SignatureBuilder::falcon_512()
        .with_secret_key(sk)?
        .with_message(test_message)
        .sign()
        .await?;
    let sign_time = start.elapsed();

    let start = Instant::now();
    let _verify = SignatureBuilder::falcon_512()
        .with_public_key(pk)?
        .with_message(test_message)
        .with_signature(sig.signature())
        .verify()
        .await?;
    let verify_time = start.elapsed();

    println!("  Signature: {} bytes", sig.signature_size());
    println!("  KeyGen: {:?}", keygen_time);
    println!("  Sign: {:?}", sign_time);
    println!("  Verify: {:?}", verify_time);

    Ok(())
}

/// Example: Key serialization and storage
#[tokio::test]
async fn example_key_serialization() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Key Serialization Example ===");

    let test_dir = "/tmp/pq_keys";
    std::fs::create_dir_all(test_dir).ok();

    // Generate keys
    let kem_kp = KemBuilder::ml_kem_768().generate().await?;
    let kem_pk = kem_kp.public_key_vec();
    let kem_sk = kem_kp.secret_key_vec();
    let sig_kp = SignatureBuilder::ml_dsa_65().generate().await?;
    let sig_pk = sig_kp.public_key_vec();
    let sig_sk = sig_kp.secret_key_vec();

    // Save KEM keys
    println!("\nSaving KEM keys...");
    let kem_pk_path = format!("{}/kem_public.key", test_dir);
    let kem_sk_path = format!("{}/kem_secret.key", test_dir);

    tokio::fs::write(
        &kem_pk_path,
        &kem_pk,
    )
    .await?;
    tokio::fs::write(
        &kem_sk_path,
        &kem_sk,
    )
    .await?;

    // Save signature keys as base64
    println!("Saving signature keys as base64...");
    let sig_pk_path = format!("{}/sig_public.b64", test_dir);
    let sig_sk_path = format!("{}/sig_secret.b64", test_dir);

    use base64::Engine;
    let sig_pk_b64 = base64::engine::general_purpose::STANDARD
        .encode(&sig_pk);
    let sig_sk_b64 = base64::engine::general_purpose::STANDARD
        .encode(&sig_sk);

    tokio::fs::write(&sig_pk_path, sig_pk_b64).await?;
    tokio::fs::write(&sig_sk_path, sig_sk_b64).await?;

    println!("Keys saved to: {}", test_dir);

    // Load and use the keys
    println!("\nLoading and using saved keys...");

    // Load KEM keys
    let loaded_kem_pk = tokio::fs::read(&kem_pk_path).await?;
    let loaded_kem_sk = tokio::fs::read(&kem_sk_path).await?;

    let encap = KemBuilder::ml_kem_768()
        .with_public_key(loaded_kem_pk)?
        .encapsulate()
        .await?;
    println!("✓ Successfully encapsulated with loaded KEM keys");

    // Load signature keys from base64
    let sig_pk_b64 = tokio::fs::read_to_string(&sig_pk_path).await?;
    let sig_sk_b64 = tokio::fs::read_to_string(&sig_sk_path).await?;

    let sig = SignatureBuilder::ml_dsa_65()
        .with_secret_key_base64(&sig_sk_b64)?
        .with_message(b"Test message")
        .sign()
        .await?;
    println!("✓ Successfully signed with loaded signature keys");

    // Cleanup
    std::fs::remove_dir_all(test_dir).ok();

    Ok(())
}

/// Example: Error handling
#[tokio::test]
async fn example_error_handling() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Error Handling Example ===");

    // Example 1: Invalid key size
    println!("\n1. Handling invalid key size:");
    let invalid_key = vec![0u8; 100];
    match KemBuilder::ml_kem_768().with_public_key(invalid_key) {
        Ok(_) => println!("Unexpected success"),
        Err(CryptError::InvalidKeySize { expected, actual }) => {
            println!(
                "✓ Caught error: Expected {} bytes, got {}",
                expected, actual
            );
        }
        Err(e) => println!("Unexpected error: {}", e),
    }

    // Example 2: Invalid algorithm
    println!("\n2. Handling invalid algorithm:");
    match KemBuilder::ml_kem(2048) {
        Ok(_) => println!("Unexpected success"),
        Err(CryptError::UnsupportedAlgorithm(msg)) => {
            println!("✓ Caught error: {}", msg);
        }
        Err(e) => println!("Unexpected error: {}", e),
    }

    // Example 3: Signature verification failure
    println!("\n3. Handling signature verification failure:");
    let keypair = SignatureBuilder::falcon_512().generate().await?;
    let pk = keypair.public_key_vec();
    let sk = keypair.secret_key_vec();
    let sig = SignatureBuilder::falcon_512()
        .with_secret_key(sk)?
        .with_message(b"original")
        .sign()
        .await?;

    let verify_result = SignatureBuilder::falcon_512()
        .with_public_key(pk)?
        .with_message(b"tampered")
        .with_signature(sig.signature())
        .verify()
        .await?;

    match verify_result.to_result() {
        Ok(_) => println!("Unexpected success"),
        Err(CryptError::AuthenticationFailed(msg)) => {
            println!("✓ Caught error: {}", msg);
        }
        Err(e) => println!("Unexpected error: {}", e),
    }

    Ok(())
}
