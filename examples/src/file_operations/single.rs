//! Single file encryption/decryption examples
//!
//! Demonstrates low-level file operations with manual file I/O.

use crate::file_operations::Key;
use cryypt::{Cipher, KeyRetriever, FileKeyStore, on_result};
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::error::Error;

/// Example 2: Single File Encryption/Decryption
pub async fn example_single_file_ops(master_key: Vec<u8>) -> Result<(), Box<dyn Error>> {
    println!("\n=== Example 2: Single File Encryption/Decryption ===");
    
    // Encrypt file to file
    encrypt_file("/tmp/input.txt", "/tmp/output.enc", master_key.clone()).await?;
    
    // Decrypt file to file
    decrypt_file("/tmp/output.enc", "/tmp/decrypted.txt", master_key).await?;
    
    Ok(())
}

/// Encrypt file to file
pub async fn encrypt_file(input_path: &str, output_path: &str, master_key: Vec<u8>) -> Result<(), Box<dyn Error>> {
    // Create test input file
    tokio::fs::write(input_path, b"File content to encrypt").await?;
    
    // Retrieve key
    let store = FileKeyStore::at("/tmp/secure/keys").with_master_key(master_key);
    let key = KeyRetriever::new()
        .with_store(store)
        .with_namespace("my-app")
        .version(1)
        .retrieve(|result| {
            Ok => Ok(result),
            Err(e) => Err(e)
        })
        .await; // Returns fully unwrapped value - no Result wrapper
    
    // Read entire file
    let mut input_file = File::open(input_path).await?;
    let mut plaintext = Vec::new();
    input_file.read_to_end(&mut plaintext).await?;
    
    // Encrypt
    let encrypted = Cipher::aes()
        .with_key(key)
        .on_result!(|result| {
            Ok => Ok(result),
            Err(e) => Err(e)
        })
        .encrypt(&plaintext)
        .await; // Returns fully unwrapped value - no Result wrapper
    
    // Write encrypted file
    let mut output_file = File::create(output_path).await?;
    output_file.write_all(&encrypted).await?;
    
    println!("Encrypted {} -> {}", input_path, output_path);
    Ok(())
}

/// Decrypt file to file
pub async fn decrypt_file(input_path: &str, output_path: &str, master_key: Vec<u8>) -> Result<(), Box<dyn Error>> {
    // Retrieve key
    let store = FileKeyStore::at("/tmp/secure/keys").with_master_key(master_key);
    let key = KeyRetriever::new()
        .with_store(store)
        .with_namespace("my-app")
        .version(1)
        .retrieve(|result| {
            Ok => Ok(result),
            Err(e) => Err(e)
        })
        .await; // Returns fully unwrapped value - no Result wrapper
    
    // Read encrypted file
    let mut input_file = File::open(input_path).await?;
    let mut ciphertext = Vec::new();
    input_file.read_to_end(&mut ciphertext).await?;
    
    // Decrypt
    let plaintext = Cipher::aes()
        .with_key(key)
        .on_result!(|result| {
            Ok => Ok(result),
            Err(e) => Err(e)
        })
        .decrypt(&ciphertext)
        .await; // Returns fully unwrapped value - no Result wrapper
    
    // Write decrypted file
    let mut output_file = File::create(output_path).await?;
    output_file.write_all(&plaintext).await?;
    
    println!("Decrypted {} -> {}", input_path, output_path);
    Ok(())
}