//! Key API examples - EXACTLY matching key/README.md

use cryypt::{Cryypt, FileKeyStore, on_result, Bits, KeyGenerator, KeyRetriever};

/// Key Generation and Retrieval example from README
async fn key_generation_and_retrieval() -> Result<(), Box<dyn std::error::Error>> {
    let master_key = [0u8; 32]; // Example master key
    
    // Generate a NEW key (one-time setup)
    let store = FileKeyStore::at("/secure/keys").with_master_key(master_key);
    let key = Cryypt::key()
        .generate()
        .size(256.bits())
        .with_store(store.clone())
        .with_namespace("my-app")
        .version(1)
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("Key generation error: {}", e))
        })
        .await; // Returns Key - the actual key object, fully unwrapped

    // Retrieve EXISTING key (normal usage)
    let key = Cryypt::key()
        .retrieve()
        .with_store(store)
        .with_namespace("my-app")
        .version(1)
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("Key generation error: {}", e))
        })
        .await; // Returns fully unwrapped value - no Result wrapper

    // Use key directly for encryption
    let encrypted = key
        .aes()
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("Operation error: {}", e))
        })
        .encrypt(b"Secret message")
        .await; // Returns Vec<u8> - the encrypted bytes, fully unwrapped

    // Use key directly for decryption
    let plaintext = key
        .aes()
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("Operation error: {}", e))
        })
        .decrypt(&encrypted)
        .await; // Returns Vec<u8> - the decrypted plaintext bytes, fully unwrapped

    // Or use ChaCha20
    let encrypted = key
        .chacha20()
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("Operation error: {}", e))
        })
        .encrypt(b"Secret message")
        .await; // Returns fully unwrapped value - no Result wrapper

    // Alternative: Direct builders are also available
    let key = KeyRetriever::new()
        .with_store(store)
        .with_namespace("my-app")
        .version(1)
        .retrieve(|result| {
            result.unwrap_or_else(|e| panic!("Operation error: {}", e))
        })
        .await; // Returns fully unwrapped value - no Result wrapper

    println!("Key operations completed successfully");
    Ok(())
}

/// Key Rotation example from README
async fn key_rotation_example() -> Result<(), Box<dyn std::error::Error>> {
    let master_key = [0u8; 32];
    let store = FileKeyStore::at("/secure/keys").with_master_key(master_key);
    
    // Generate new key version
    let new_key = Cryypt::key()
        .generate()
        .size(256.bits())
        .with_store(store.clone())
        .with_namespace("my-app")
        .version(2) // New version
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("Key generation error: {}", e))
        })
        .await; // Returns fully unwrapped value - no Result wrapper

    // Re-encrypt data with new key
    let old_key = Cryypt::key()
        .retrieve()
        .with_store(store)
        .with_namespace("my-app")
        .version(1) // Old version
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("Key generation error: {}", e))
        })
        .await; // Returns fully unwrapped value - no Result wrapper

    // Example ciphertext (in real app, this would be loaded from storage)
    let ciphertext = old_key
        .aes()
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("Operation error: {}", e))
        })
        .encrypt(b"Secret data")
        .await;

    // Decrypt with old key
    let plaintext = Cryypt::cipher()
        .aes()
        .with_key(old_key)
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("Operation error: {}", e))
        })
        .decrypt(ciphertext)
        .await; // Returns fully unwrapped value - no Result wrapper

    // Re-encrypt with new key
    let new_ciphertext = Cryypt::cipher()
        .aes()
        .with_key(new_key)
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("Operation error: {}", e))
        })
        .encrypt(plaintext)
        .await; // Returns fully unwrapped value - no Result wrapper

    println!("Key rotation completed successfully");
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Key Generation and Retrieval ===");
    key_generation_and_retrieval().await?;
    
    println!("\n=== Key Rotation ===");
    key_rotation_example().await?;
    
    Ok(())
}