//! Advanced Patterns Examples - Exactly matching README.md patterns
//! These examples demonstrate error recovery, pipelines, parallel processing, and key rotation

use cryypt::{Cryypt, FileKeyStore, on_result, Bits};
use futures::future::try_join_all;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    
    // Create a master key for the key store
    let master_key = vec![0u8; 32]; // In production, use a secure master key
    
    // Example 1: Custom error recovery
    example_custom_error_recovery(master_key.clone()).await?;
    
    // Example 2: Pipeline processing
    example_pipeline_processing(master_key.clone()).await?;
    
    // Example 3: Parallel processing
    example_parallel_processing().await?;
    
    // Example 4: Key rotation
    example_key_rotation(master_key).await?;
    
    Ok(())
}

async fn example_custom_error_recovery(master_key: Vec<u8>) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n=== Example 1: Custom Error Recovery ===");
    
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
    
    let data = b"Data to encrypt with retry logic";
    
    // Retry with exponential backoff
    let encrypted = Cryypt::cipher()
        .aes()
        .with_key(key)
        .on_result!(|result| {
            Ok => Ok(result),
            Err(e) => {
                if e.is_transient() {
                    // Handle transient error
                    println!("Transient error detected, would retry...");
                    retry_operation()
                } else {
                    Err(e)
                }
            }
        })
        .encrypt(data)
        .await; // Returns fully unwrapped value - no Result wrapper
    
    println!("Encrypted with retry logic: {} bytes", encrypted.len());
    
    Ok(())
}

async fn example_pipeline_processing(master_key: Vec<u8>) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n=== Example 2: Pipeline Processing ===");
    
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
    
    let data = b"Data for pipeline processing";
    
    // Hash -> Compress -> Encrypt pipeline
    let hash = Cryypt::hash()
        .sha256()
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("Operation error: {}", e))
        })
        .compute(data)
        .await; // Returns fully unwrapped value - no Result wrapper
    
    println!("Step 1 - Hash: {} bytes", hash.len());
    
    let compressed = Cryypt::compress()
        .zstd()
        .with_level(3)
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("Operation error: {}", e))
        })
        .compress(data)
        .await; // Returns fully unwrapped value - no Result wrapper
    
    println!("Step 2 - Compressed: {} bytes", compressed.len());
    
    let encrypted = Cryypt::cipher()
        .aes()
        .with_key(key)
        .with_aad(&hash) // Use hash as additional authenticated data
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("Operation error: {}", e))
        })
        .encrypt(&compressed)
        .await; // Returns fully unwrapped value - no Result wrapper
    
    println!("Step 3 - Encrypted with AAD: {} bytes", encrypted.len());
    println!("Pipeline complete!");
    
    Ok(())
}

async fn example_parallel_processing() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n=== Example 3: Parallel Processing ===");
    
    // Create test files
    let files = vec!["/tmp/file1.txt", "/tmp/file2.txt", "/tmp/file3.txt"];
    for (i, file) in files.iter().enumerate() {
        tokio::fs::write(file, format!("Content of file {}", i + 1)).await?;
    }
    
    // Hash multiple files in parallel
    let hashes = try_join_all(
        files.into_iter().map(|file| async move {
            let content = tokio::fs::read(file).await?;
            let hash = Cryypt::hash()
                .sha256()
                .on_result!(|result| {
                    result.unwrap_or_else(|e| panic!("Hash error: {}", e))
                })
                .compute(content)
                .await;
            
            Ok::<(String, Vec<u8>), Box<dyn std::error::Error>>((file.to_string(), hash))
        })
    ).await?;
    
    // Print results
    for (file, hash) in hashes {
        println!("File: {} -> Hash: {} bytes", file, hash.len());
    }
    
    Ok(())
}

async fn example_key_rotation(master_key: Vec<u8>) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n=== Example 4: Key Rotation ===");
    
    let store = FileKeyStore::at("/tmp/secure/keys").with_master_key(master_key);
    
    // Create some test data encrypted with old key
    let test_data = b"Sensitive data that needs re-encryption";
    
    // First, ensure we have version 1 key
    let old_key = Cryypt::key()
        .generate()
        .size(256.bits())
        .with_store(store.clone())
        .with_namespace("my-app")
        .version(1)
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("Key generation error: {}", e))
        })
        .await;
    
    // Encrypt with old key
    let ciphertext = Cryypt::cipher()
        .aes()
        .with_key(old_key.clone())
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("Operation error: {}", e))
        })
        .encrypt(test_data)
        .await;
    
    println!("Data encrypted with version 1 key");
    
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
    
    println!("Generated new key version 2");
    
    // Re-encrypt data with new key
    let old_key = Cryypt::key()
        .retrieve()
        .with_store(store.clone())
        .with_namespace("my-app")
        .version(1) // Old version
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("Key generation error: {}", e))
        })
        .await; // Returns fully unwrapped value - no Result wrapper
    
    // Decrypt with old key
    let plaintext = Cryypt::cipher()
        .aes()
        .with_key(old_key)
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("Operation error: {}", e))
        })
        .decrypt(&ciphertext)
        .await; // Returns fully unwrapped value - no Result wrapper
    
    println!("Decrypted with old key");
    
    // Re-encrypt with new key
    let new_ciphertext = Cryypt::cipher()
        .aes()
        .with_key(new_key)
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("Operation error: {}", e))
        })
        .encrypt(&plaintext)
        .await; // Returns fully unwrapped value - no Result wrapper
    
    println!("Re-encrypted with new key version 2");
    println!("Key rotation complete!");
    
    Ok(())
}

// Mock retry function
fn retry_operation() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    // In real implementation, this would retry with exponential backoff
    Ok(vec![1, 2, 3, 4])
}

// Extension trait for error checking (mock)
trait ErrorExt {
    fn is_transient(&self) -> bool;
}

impl ErrorExt for Box<dyn std::error::Error> {
    fn is_transient(&self) -> bool {
        // In real implementation, check if error is retryable
        false
    }
}