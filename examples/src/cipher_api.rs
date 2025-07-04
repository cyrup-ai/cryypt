//! Cipher API Examples - Exactly matching README.md patterns
//! These examples demonstrate AES and ChaCha20 encryption with fully unwrapped returns

use cryypt::{Cryypt, FileKeyStore, on_result, on_chunk};
use tokio_stream::{Stream, StreamExt};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    
    // Create a master key for the key store
    let master_key = vec![0u8; 32]; // In production, use a secure master key
    
    // Example 1: AES-256-GCM Encryption
    example_aes_encryption(master_key.clone()).await?;
    
    // Example 2: Stream encryption for large files
    example_stream_encryption(master_key.clone()).await?;
    
    // Example 3: ChaCha20-Poly1305 Encryption
    example_chacha20_encryption(master_key.clone()).await?;
    
    Ok(())
}

async fn example_aes_encryption(master_key: Vec<u8>) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n=== Example 1: AES-256-GCM Encryption ===");
    
    // Retrieve key for encryption/decryption
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
    
    // Encrypt data
    let encrypted = Cryypt::cipher()
        .aes()
        .with_key(key.clone())
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("Operation error: {}", e))
        })
        .encrypt(b"Secret message")
        .await; // Returns fully unwrapped value - no Result wrapper
    
    println!("Encrypted: {} bytes", encrypted.len());
    
    // Decrypt data  
    let plaintext = Cryypt::cipher()
        .aes()
        .with_key(key)
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("Operation error: {}", e))
        })
        .decrypt(&encrypted)
        .await; // Returns fully unwrapped value - no Result wrapper
    
    println!("Decrypted: {}", String::from_utf8_lossy(&plaintext));
    
    Ok(())
}

async fn example_stream_encryption(master_key: Vec<u8>) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n=== Example 2: Stream encryption for large files ===");
    
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
    
    // Create a sample input stream
    let input_data = vec![b"Chunk 1".to_vec(), b"Chunk 2".to_vec(), b"Chunk 3".to_vec()];
    let input_stream = tokio_stream::iter(input_data.clone());
    
    // Stream encryption for large files
    let mut encrypted_stream = Cryypt::cipher()
        .aes()
        .with_key(key.clone())
        .on_chunk!(|chunk| {
            Ok => chunk,  // Unwrapped encrypted bytes
            Err(e) => {
                log::error!("Encryption chunk error: {}", e);
                return;
            }
        })
        .encrypt_stream(input_stream); // Returns Stream<Item = Vec<u8>> - fully unwrapped encrypted chunks
    
    // Collect encrypted chunks
    let mut encrypted_chunks = Vec::new();
    while let Some(chunk) = encrypted_stream.next().await {
        // chunk is Vec<u8> - already unwrapped by on_chunk!
        println!("Encrypted chunk: {} bytes", chunk.len());
        encrypted_chunks.push(chunk);
    }
    
    // Create encrypted stream for decryption
    let encrypted_file_stream = tokio_stream::iter(encrypted_chunks);
    
    // Stream decryption (from encrypted file)
    let mut decrypted_stream = Cryypt::cipher()
        .aes()
        .with_key(key)
        .on_chunk!(|chunk| {
            Ok => chunk,
            Err(e) => {
                log::error!("Decryption chunk error: {}", e);
                return;
            }
        })
        .decrypt_stream(encrypted_file_stream);
    
    // Collect decrypted chunks
    println!("\nDecrypted chunks:");
    while let Some(chunk) = decrypted_stream.next().await {
        println!("  {}", String::from_utf8_lossy(&chunk));
    }
    
    Ok(())
}

async fn example_chacha20_encryption(master_key: Vec<u8>) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n=== Example 3: ChaCha20-Poly1305 Encryption ===");
    
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
    
    // Encrypt with ChaCha20
    let encrypted = Cryypt::cipher()
        .chacha20()
        .with_key(key.clone())
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("Operation error: {}", e))
        })
        .encrypt(b"Secret message")
        .await; // Returns fully unwrapped value - no Result wrapper
    
    println!("ChaCha20 encrypted: {} bytes", encrypted.len());
    
    // Decrypt with custom error handling
    let plaintext = Cryypt::cipher()
        .chacha20()
        .with_key(key) 
        .on_result!(|result| {
            result.unwrap_or_else(|e| {
                log::error!("Decryption failed: {}", e);
                panic!("Decryption failed: {}", e)
            })
        })
        .decrypt(&encrypted)
        .await; // Returns fully unwrapped value - no Result wrapper
    
    println!("ChaCha20 decrypted: {}", String::from_utf8_lossy(&plaintext));
    
    Ok(())
}