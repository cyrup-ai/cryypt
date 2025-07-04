//! Key API Examples - Exactly matching README.md patterns
//! These examples demonstrate key generation and retrieval with fully unwrapped returns

use cryypt::{Cryypt, FileKeyStore, on_result, Bits, KeyGenerator, KeyRetriever};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    
    // Create a master key for the key store
    let master_key = vec![0u8; 32]; // In production, use a secure master key
    
    // Example 1: Generate a NEW key (one-time setup)
    example_generate_key(master_key.clone()).await?;
    
    // Example 2: Retrieve EXISTING key (normal usage)
    example_retrieve_key(master_key.clone()).await?;
    
    // Example 3: Use key directly for encryption/decryption
    example_key_encryption(master_key.clone()).await?;
    
    // Example 4: Alternative direct builder API
    example_direct_builder_api(master_key.clone()).await?;
    
    Ok(())
}

async fn example_generate_key(master_key: Vec<u8>) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n=== Example 1: Generate a NEW key ===");
    
    // Generate a NEW key (one-time setup)
    let store = FileKeyStore::at("/tmp/secure/keys").with_master_key(master_key);
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
    
    println!("Generated key: {:?}", key);
    
    Ok(())
}

async fn example_retrieve_key(master_key: Vec<u8>) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n=== Example 2: Retrieve EXISTING key ===");
    
    // Retrieve EXISTING key (normal usage)
    let store = FileKeyStore::at("/tmp/secure/keys").with_master_key(master_key);
    let key = Cryypt::key()
        .retrieve()
        .with_store(store)
        .with_namespace("my-app")
        .version(1)
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("Key generation error: {}", e))
        })
        .await; // Returns fully unwrapped value - no Result wrapper
    
    println!("Retrieved key: {:?}", key);
    
    Ok(())
}

async fn example_key_encryption(master_key: Vec<u8>) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n=== Example 3: Use key directly for encryption/decryption ===");
    
    // First retrieve the key
    let store = FileKeyStore::at("/tmp/secure/keys").with_master_key(master_key);
    let key = Cryypt::key()
        .retrieve()
        .with_store(store)
        .with_namespace("my-app")
        .version(1)
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("Key retrieval error: {}", e))
        })
        .await;
    
    // Use key directly for encryption
    let encrypted = key
        .aes()
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("Operation error: {}", e))
        })
        .encrypt(b"Secret message")
        .await; // Returns Vec<u8> - the encrypted bytes, fully unwrapped
    
    println!("Encrypted: {} bytes", encrypted.len());
    
    // Use key directly for decryption
    let plaintext = key
        .aes()
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("Operation error: {}", e))
        })
        .decrypt(&encrypted)
        .await; // Returns Vec<u8> - the decrypted plaintext bytes, fully unwrapped
    
    println!("Decrypted: {}", String::from_utf8_lossy(&plaintext));
    
    // Or use ChaCha20
    let encrypted = key
        .chacha20()
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("Operation error: {}", e))
        })
        .encrypt(b"Secret message")
        .await; // Returns fully unwrapped value - no Result wrapper
    
    println!("ChaCha20 encrypted: {} bytes", encrypted.len());
    
    Ok(())
}

async fn example_direct_builder_api(master_key: Vec<u8>) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n=== Example 4: Alternative direct builder API ===");
    
    // Alternative: Direct builders are also available
    let store = FileKeyStore::at("/tmp/secure/keys").with_master_key(master_key);
    let key = KeyRetriever::new()
        .with_store(store)
        .with_namespace("my-app")
        .version(1)
        .retrieve(|result| {
            result.unwrap_or_else(|e| panic!("Operation error: {}", e))
        })
        .await; // Returns fully unwrapped value - no Result wrapper
    
    println!("Retrieved key using direct builder: {:?}", key);
    
    Ok(())
}