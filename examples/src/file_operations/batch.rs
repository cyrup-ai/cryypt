//! Multiple files and batch processing examples
//!
//! Demonstrates parallel file processing and archive compression with encryption.

use crate::file_operations::Key;
use cryypt::{Cipher, KeyRetriever, FileKeyStore, Compress, on_result};
use futures::future::try_join_all;
use std::path::Path;
use std::error::Error;

/// Example 4: Multiple Files Processing
pub async fn example_multiple_files(master_key: Vec<u8>) -> Result<(), Box<dyn Error>> {
    println!("\n=== Example 4: Multiple Files Processing ===");
    
    // Create test directory with files
    tokio::fs::create_dir_all("/tmp/input_files").await?;
    tokio::fs::create_dir_all("/tmp/output_files").await?;
    
    for i in 1..=3 {
        let path = format!("/tmp/input_files/file{}.txt", i);
        let content = format!("Content of file {}", i);
        tokio::fs::write(&path, content.as_bytes()).await?;
    }
    
    encrypt_files("/tmp/input_files", "/tmp/output_files", master_key).await?;
    
    Ok(())
}

/// Encrypt multiple files in parallel
pub async fn encrypt_files(input_dir: &str, output_dir: &str, master_key: Vec<u8>) -> Result<(), Box<dyn Error>> {
    // Retrieve key once
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
    
    // Get all files
    let mut entries = tokio::fs::read_dir(input_dir).await?;
    let mut tasks = Vec::new();
    
    while let Some(entry) = entries.next_entry().await? {
        let path = entry.path();
        if path.is_file() {
            let input_path = path.clone();
            let output_path = Path::new(output_dir)
                .join(format!("{}.enc", path.file_name().unwrap().to_str().unwrap()));
            let key = Key(key.0.clone()); // Clone for move
            
            // Spawn encryption task
            tasks.push(tokio::spawn(async move {
                encrypt_file_with_key(input_path, output_path, key).await
            }));
        }
    }
    
    // Wait for all encryptions to complete
    try_join_all(tasks).await?;
    println!("All files encrypted successfully");
    Ok(())
}

/// Helper function for parallel file encryption
pub async fn encrypt_file_with_key(
    input_path: std::path::PathBuf,
    output_path: std::path::PathBuf,
    key: Key
) -> Result<(), Box<dyn Error>> {
    // Read file
    let plaintext = tokio::fs::read(&input_path).await?;
    
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
    tokio::fs::write(&output_path, encrypted).await?;
    
    println!("Encrypted: {} -> {}", input_path.display(), output_path.display());
    Ok(())
}

/// Example 5: Batch Compress and Encrypt
pub async fn example_batch_compress_encrypt(master_key: Vec<u8>) -> Result<(), Box<dyn Error>> {
    println!("\n=== Example 5: Batch Compress and Encrypt ===");
    
    let files = vec!["/tmp/file1.txt", "/tmp/file2.txt", "/tmp/file3.txt"];
    
    // Create test files
    for (i, file) in files.iter().enumerate() {
        tokio::fs::write(file, format!("Content of file {}", i + 1)).await?;
    }
    
    compress_and_encrypt_files(files, "/tmp/archive.enc", master_key).await?;
    
    Ok(())
}

/// Batch compress and encrypt files
pub async fn compress_and_encrypt_files(
    files: Vec<&str>,
    output_archive: &str,
    master_key: Vec<u8>
) -> Result<(), Box<dyn Error>> {
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
    
    // Create ZIP archive
    let mut archive = Compress::zip();
    
    // Add all files
    for file_path in files {
        let content = tokio::fs::read(file_path).await?;
        let file_name = Path::new(file_path).file_name().unwrap().to_str().unwrap();
        archive = archive.add_file(file_name, content);
    }
    
    // Compress
    let compressed = archive
        .on_result!(|result| {
            Ok => Ok(result),
            Err(e) => Err(e)
        })
        .compress()
        .await; // Returns fully unwrapped value - no Result wrapper
    
    println!("Created ZIP archive: {} bytes", compressed.len());
    
    // Encrypt the archive
    let encrypted = Cipher::aes()
        .with_key(key)
        .on_result!(|result| {
            Ok => Ok(result),
            Err(e) => Err(e)
        })
        .encrypt(&compressed)
        .await; // Returns fully unwrapped value - no Result wrapper
    
    // Write encrypted archive
    tokio::fs::write(output_archive, encrypted).await?;
    
    println!("Encrypted archive saved to: {}", output_archive);
    Ok(())
}