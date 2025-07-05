//! Post-Quantum Cryptography API examples - EXACTLY matching pqcrypto/README.md

use cryypt::{Cryypt, on_result};

/// Kyber Key Exchange example from README
async fn kyber_key_exchange() -> Result<(), Box<dyn std::error::Error>> {
    // Kyber key exchange
    let (public_key, secret_key) = Cryypt::pqcrypto()
        .kyber()
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("Operation error: {}", e))
        })
        .generate_keypair()
        .await; // Returns fully unwrapped value - no Result wrapper

    // Encapsulate shared secret
    let (ciphertext, shared_secret) = Cryypt::pqcrypto()
        .kyber()
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("Operation error: {}", e))
        })
        .encapsulate(public_key)
        .await; // Returns fully unwrapped value - no Result wrapper

    // Decapsulate shared secret
    let shared_secret = Cryypt::pqcrypto()
        .kyber()
        .with_secret_key(secret_key)
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("Operation error: {}", e))
        })
        .decapsulate(ciphertext)
        .await; // Returns fully unwrapped value - no Result wrapper

    println!("Kyber key exchange completed successfully");
    Ok(())
}

/// Dilithium Signatures example from README
async fn dilithium_signatures() -> Result<(), Box<dyn std::error::Error>> {
    let message = b"Important message to sign";
    
    // Dilithium signatures
    let (public_key, secret_key) = Cryypt::pqcrypto()
        .dilithium()
        .with_security_level(3)
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("Operation error: {}", e))
        })
        .generate_keypair()
        .await; // Returns fully unwrapped value - no Result wrapper

    let signature = Cryypt::pqcrypto()
        .dilithium()
        .with_secret_key(secret_key)
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("Operation error: {}", e))
        })
        .sign(message)
        .await; // Returns fully unwrapped value - no Result wrapper

    let valid = Cryypt::pqcrypto()
        .dilithium()
        .with_public_key(public_key)
        .with_signature(signature)
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("Operation error: {}", e))
        })
        .verify(message)
        .await; // Returns fully unwrapped value - no Result wrapper

    println!("Dilithium signature valid: {}", valid);
    Ok(())
}

/// Secure Multi-party Communication example from README
async fn secure_multiparty_communication() -> Result<(), Box<dyn std::error::Error>> {
    // Alice generates keypair
    let (alice_public, alice_secret) = Cryypt::pqcrypto()
        .kyber()
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("Operation error: {}", e))
        })
        .generate_keypair()
        .await; // Returns fully unwrapped value - no Result wrapper

    // Bob encapsulates shared secret
    let (ciphertext, bob_shared_secret) = Cryypt::pqcrypto()
        .kyber()
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("Operation error: {}", e))
        })
        .encapsulate(alice_public)
        .await; // Returns fully unwrapped value - no Result wrapper

    // Alice decapsulates to get same shared secret
    let alice_shared_secret = Cryypt::pqcrypto()
        .kyber()
        .with_secret_key(alice_secret)
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("Operation error: {}", e))
        })
        .decapsulate(ciphertext)
        .await; // Returns fully unwrapped value - no Result wrapper

    // Now both can use shared secret for symmetric encryption
    let encrypted = Cryypt::cipher()
        .aes()
        .with_key(bob_shared_secret)
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("Operation error: {}", e))
        })
        .encrypt(b"Secret message")
        .await; // Returns fully unwrapped value - no Result wrapper

    // Alice can decrypt using her shared secret
    let decrypted = Cryypt::cipher()
        .aes()
        .with_key(alice_shared_secret)
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("Operation error: {}", e))
        })
        .decrypt(&encrypted)
        .await; // Returns fully unwrapped value - no Result wrapper

    println!("Decrypted message: {:?}", String::from_utf8(decrypted)?);
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Kyber Key Exchange ===");
    kyber_key_exchange().await?;
    
    println!("\n=== Dilithium Signatures ===");
    dilithium_signatures().await?;
    
    println!("\n=== Secure Multi-party Communication ===");
    secure_multiparty_communication().await?;
    
    Ok(())
}