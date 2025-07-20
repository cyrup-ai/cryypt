use cryypt::{Cryypt, on_result};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Post-Quantum Cryptography Examples");
    
    // Demo 1: Kyber key exchange
    println!("\n=== Kyber Key Exchange Demo ===");
    
    // Generate keypair
    let (public_key, secret_key) = Cryypt::pqcrypto()
        .kyber()
        .on_result(|result| {
            Ok => result,
            Err(e) => {
                log::error!("Kyber keypair generation error: {}", e);
                (Vec::new(), Vec::new()) // Return empty keys on error
            }
        })
        .generate_keypair()
        .await; // Returns fully unwrapped value - no Result wrapper

    println!("Kyber keypair generated:");
    println!("  Public key size: {} bytes", public_key.len());
    println!("  Secret key size: {} bytes", secret_key.len());

    // Encapsulate shared secret
    let (ciphertext, shared_secret) = Cryypt::pqcrypto()
        .kyber()
        .on_result(|result| {
            Ok => result,
            Err(e) => {
                log::error!("Kyber encapsulation error: {}", e);
                (Vec::new(), Vec::new()) // Return empty on error
            }
        })
        .encapsulate(public_key.clone())
        .await; // Returns fully unwrapped value - no Result wrapper

    println!("Encapsulation completed:");
    println!("  Ciphertext size: {} bytes", ciphertext.len());
    println!("  Shared secret size: {} bytes", shared_secret.len());

    // Decapsulate shared secret
    let decapsulated_secret = Cryypt::pqcrypto()
        .kyber()
        .with_secret_key(secret_key.clone())
        .on_result(|result| {
            Ok => result,
            Err(e) => {
                log::error!("Kyber decapsulation error: {}", e);
                Vec::new() // Return empty on error
            }
        })
        .decapsulate(ciphertext.clone())
        .await; // Returns fully unwrapped value - no Result wrapper

    println!("Decapsulation completed:");
    println!("  Decapsulated secret size: {} bytes", decapsulated_secret.len());
    println!("  Secrets match: {}", if shared_secret == decapsulated_secret { "✅ YES" } else { "❌ NO" });

    // Demo 2: Dilithium signatures
    println!("\n=== Dilithium Digital Signatures Demo ===");
    
    let message = b"Important message that needs to be signed";
    
    let (sig_public_key, sig_secret_key) = Cryypt::pqcrypto()
        .dilithium()
        .with_security_level(3)
        .on_result(|result| {
            Ok => result,
            Err(e) => {
                log::error!("Dilithium keypair generation error: {}", e);
                (Vec::new(), Vec::new()) // Return empty keys on error
            }
        })
        .generate_keypair()
        .await; // Returns fully unwrapped value - no Result wrapper

    println!("Dilithium keypair generated:");
    println!("  Public key size: {} bytes", sig_public_key.len());
    println!("  Secret key size: {} bytes", sig_secret_key.len());

    let signature = Cryypt::pqcrypto()
        .dilithium()
        .with_secret_key(sig_secret_key.clone())
        .on_result(|result| {
            Ok => result,
            Err(e) => {
                log::error!("Dilithium signing error: {}", e);
                Vec::new() // Return empty signature on error
            }
        })
        .sign(message)
        .await; // Returns fully unwrapped value - no Result wrapper

    println!("Message signed:");
    println!("  Message: {}", String::from_utf8_lossy(message));
    println!("  Signature size: {} bytes", signature.len());

    let valid = Cryypt::pqcrypto()
        .dilithium()
        .with_public_key(sig_public_key.clone())
        .with_signature(signature.clone())
        .on_result(|result| {
            Ok => result,
            Err(e) => {
                log::error!("Dilithium verification error: {}", e);
                false // Return false on error
            }
        })
        .verify(message)
        .await; // Returns fully unwrapped value - no Result wrapper

    println!("Signature verification: {}", if valid { "✅ VALID" } else { "❌ INVALID" });

    // Demo 3: Complete key exchange scenario
    println!("\n=== Complete Key Exchange Scenario ===");
    
    // Alice generates keypair
    let (alice_public, alice_secret) = Cryypt::pqcrypto()
        .kyber()
        .on_result(|result| {
            Ok => result,
            Err(e) => {
                log::error!("Alice keypair generation error: {}", e);
                (Vec::new(), Vec::new())
            }
        })
        .generate_keypair()
        .await; // Returns fully unwrapped value - no Result wrapper

    println!("Alice generated Kyber keypair");

    // Bob encapsulates shared secret using Alice's public key
    let (bob_ciphertext, bob_shared_secret) = Cryypt::pqcrypto()
        .kyber()
        .on_result(|result| {
            Ok => result,
            Err(e) => {
                log::error!("Bob encapsulation error: {}", e);
                (Vec::new(), Vec::new())
            }
        })
        .encapsulate(alice_public)
        .await; // Returns fully unwrapped value - no Result wrapper

    println!("Bob encapsulated shared secret");

    // Alice decapsulates to get same shared secret
    let alice_shared_secret = Cryypt::pqcrypto()
        .kyber()
        .with_secret_key(alice_secret)
        .on_result(|result| {
            match result {
                Ok(result) => result,
                Err(e) => {
                    log::error!("Alice decapsulation error: {}", e);
                    Vec::new()
                }
            }
        })
        .decapsulate(bob_ciphertext)
        .await; // Returns fully unwrapped value - no Result wrapper

    println!("Alice decapsulated shared secret");
    println!("Shared secrets match: {}", if bob_shared_secret == alice_shared_secret { "✅ YES" } else { "❌ NO" });

    // Now both can use shared secret for symmetric encryption
    let secret_message = b"Secret message using post-quantum shared secret";
    
    // Pad the shared secret to 32 bytes for AES-256 (if needed)
    let mut encryption_key = bob_shared_secret;
    encryption_key.resize(32, 0); // Pad or truncate to 32 bytes
    
    let encrypted = Cryypt::cipher()
        .aes()
        .with_key(encryption_key.clone())
        .on_result(|result| {
            match result {
                Ok(result) => result,
                Err(e) => {
                    log::error!("AES encryption error: {}", e);
                    Vec::new()
                }
            }
        })
        .encrypt(secret_message)
        .await; // Returns fully unwrapped value - no Result wrapper

    println!("Message encrypted with PQ-derived key:");
    println!("  Original: {}", String::from_utf8_lossy(secret_message));
    println!("  Encrypted size: {} bytes", encrypted.len());

    // Alice can decrypt using her shared secret
    let mut alice_encryption_key = alice_shared_secret;
    alice_encryption_key.resize(32, 0); // Same padding
    
    let decrypted = Cryypt::cipher()
        .aes()
        .with_key(alice_encryption_key)
        .on_result(|result| {
            match result {
                Ok(result) => result,
                Err(e) => {
                    log::error!("AES decryption error: {}", e);
                    Vec::new()
                }
            }
        })
        .decrypt(encrypted)
        .await; // Returns fully unwrapped value - no Result wrapper

    println!("  Decrypted: {}", String::from_utf8_lossy(&decrypted));
    println!("  Message integrity: {}", if decrypted == secret_message { "✅ PASSED" } else { "❌ FAILED" });

    println!("\n🎉 Post-quantum cryptography demo completed successfully!");

    Ok(())
}