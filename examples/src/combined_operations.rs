//! Combined Operations Examples - Exactly matching README.md patterns
//! These examples demonstrate compression + encryption + hashing pipelines

use cryypt::{Cryypt, FileKeyStore, on_result};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    
    // Create a master key for the key store
    let master_key = vec![0u8; 32]; // In production, use a secure master key
    
    // Example: Compress, encrypt, and hash
    example_combined_operations(master_key).await?;
    
    Ok(())
}

async fn example_combined_operations(master_key: Vec<u8>) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n=== Combined Operations: Compress, Encrypt, and Hash ===");
    
    // Retrieve key
    let store = FileKeyStore::at("/tmp/secure/keys").with_master_key(master_key);
    let key = Cryypt::key()
        .retrieve()
        .with_store(store)
        .with_namespace("my-app")
        .version(1)
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("Key generation error: {}", e))
        })
        .await;
    
    let large_data = b"This is some large data that needs to be compressed, encrypted, and hashed.".repeat(100);
    println!("Original data size: {} bytes", large_data.len());
    
    // Compress, encrypt, and hash
    let compressed = Cryypt::compress()
        .zstd()
        .with_level(3)
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("Operation error: {}", e))
        })
        .compress(&large_data)
        .await; // Returns fully unwrapped value - no Result wrapper
    
    println!("Compressed size: {} bytes", compressed.len());
    
    let encrypted = Cryypt::cipher()
        .aes()
        .with_key(key)
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("Operation error: {}", e))
        })
        .encrypt(&compressed)
        .await; // Returns fully unwrapped value - no Result wrapper
    
    println!("Encrypted size: {} bytes", encrypted.len());
    
    let hash = Cryypt::hash()
        .sha256()
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("Operation error: {}", e))
        })
        .compute(&encrypted)
        .await; // Returns fully unwrapped value - no Result wrapper
    
    println!("Hash of encrypted data: {} bytes - {:?}", hash.len(), &hash[..8]);
    
    // Summary
    println!("\nPipeline summary:");
    println!("  Original: {} bytes", large_data.len());
    println!("  Compressed: {} bytes ({:.1}% reduction)", 
        compressed.len(), 
        (1.0 - compressed.len() as f64 / large_data.len() as f64) * 100.0
    );
    println!("  Encrypted: {} bytes", encrypted.len());
    println!("  Hash: {} bytes", hash.len());
    
    Ok(())
}