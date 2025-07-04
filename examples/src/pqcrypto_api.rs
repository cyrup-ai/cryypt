//! Post-Quantum Cryptography Examples - Exactly matching README.md patterns
//! These examples demonstrate Kyber key exchange and Dilithium signatures

use cryypt::{Cryypt, on_result};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    
    // Example 1: Kyber key exchange
    example_kyber_key_exchange().await?;
    
    // Example 2: Dilithium signatures
    example_dilithium_signatures().await?;
    
    // Example 3: Secure multi-party communication
    example_secure_multiparty().await?;
    
    Ok(())
}

async fn example_kyber_key_exchange() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n=== Example 1: Kyber Key Exchange ===");
    
    // Kyber key exchange
    let (public_key, secret_key) = Cryypt::pqcrypto()
        .kyber()
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("Operation error: {}", e))
        })
        .generate_keypair()
        .await; // Returns fully unwrapped value - no Result wrapper
    
    println!("Kyber keypair generated");
    println!("Public key size: {} bytes", public_key.len());
    println!("Secret key size: {} bytes", secret_key.len());
    
    // Encapsulate shared secret
    let (ciphertext, shared_secret) = Cryypt::pqcrypto()
        .kyber()
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("Operation error: {}", e))
        })
        .encapsulate(public_key.clone())
        .await; // Returns fully unwrapped value - no Result wrapper
    
    println!("Shared secret encapsulated");
    println!("Ciphertext size: {} bytes", ciphertext.len());
    println!("Shared secret size: {} bytes", shared_secret.len());
    
    // Decapsulate shared secret
    let decapsulated_secret = Cryypt::pqcrypto()
        .kyber()
        .with_secret_key(secret_key)
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("Operation error: {}", e))
        })
        .decapsulate(ciphertext)
        .await; // Returns fully unwrapped value - no Result wrapper
    
    println!("Shared secret decapsulated");
    println!("Secrets match: {}", shared_secret == decapsulated_secret);
    
    Ok(())
}

async fn example_dilithium_signatures() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n=== Example 2: Dilithium Signatures ===");
    
    // Dilithium signatures
    let (public_key, secret_key) = Cryypt::pqcrypto()
        .dilithium()
        .with_security_level(3)
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("Operation error: {}", e))
        })
        .generate_keypair()
        .await; // Returns fully unwrapped value - no Result wrapper
    
    println!("Dilithium keypair generated (security level 3)");
    println!("Public key size: {} bytes", public_key.len());
    println!("Secret key size: {} bytes", secret_key.len());
    
    let message = b"Important message to sign";
    
    // Sign message
    let signature = Cryypt::pqcrypto()
        .dilithium()
        .with_secret_key(secret_key)
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("Operation error: {}", e))
        })
        .sign(message)
        .await; // Returns fully unwrapped value - no Result wrapper
    
    println!("Message signed");
    println!("Signature size: {} bytes", signature.len());
    
    // Verify signature
    let valid = Cryypt::pqcrypto()
        .dilithium()
        .with_public_key(public_key)
        .with_signature(signature)
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("Operation error: {}", e))
        })
        .verify(message)
        .await; // Returns fully unwrapped value - no Result wrapper
    
    println!("Signature valid: {}", valid);
    
    Ok(())
}

async fn example_secure_multiparty() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n=== Example 3: Secure Multi-party Communication ===");
    
    // Alice generates keypair
    let (alice_public, alice_secret) = Cryypt::pqcrypto()
        .kyber()
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("Operation error: {}", e))
        })
        .generate_keypair()
        .await; // Returns fully unwrapped value - no Result wrapper
    
    println!("Alice: Generated Kyber keypair");
    
    // Bob encapsulates shared secret
    let (ciphertext, bob_shared_secret) = Cryypt::pqcrypto()
        .kyber()
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("Operation error: {}", e))
        })
        .encapsulate(alice_public)
        .await; // Returns fully unwrapped value - no Result wrapper
    
    println!("Bob: Encapsulated shared secret");
    
    // Alice decapsulates to get same shared secret
    let alice_shared_secret = Cryypt::pqcrypto()
        .kyber()
        .with_secret_key(alice_secret)
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("Operation error: {}", e))
        })
        .decapsulate(ciphertext)
        .await; // Returns fully unwrapped value - no Result wrapper
    
    println!("Alice: Decapsulated shared secret");
    println!("Shared secrets match: {}", alice_shared_secret == bob_shared_secret);
    
    // Now both can use shared secret for symmetric encryption
    let encrypted = Cryypt::cipher()
        .aes()
        .with_key(bob_shared_secret)
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("Operation error: {}", e))
        })
        .encrypt(b"Secret message")
        .await; // Returns fully unwrapped value - no Result wrapper
    
    println!("Bob: Encrypted message with shared secret");
    
    // Alice decrypts with her copy of the shared secret
    let decrypted = Cryypt::cipher()
        .aes()
        .with_key(alice_shared_secret)
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("Operation error: {}", e))
        })
        .decrypt(&encrypted)
        .await;
    
    println!("Alice: Decrypted message: {}", String::from_utf8_lossy(&decrypted));
    
    Ok(())
}