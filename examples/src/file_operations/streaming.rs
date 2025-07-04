//! Stream large file encryption examples
//!
//! Demonstrates streaming operations for large files with chunked processing.

use cryypt::{Cipher, KeyRetriever, FileKeyStore, on_chunk};
use tokio::fs::File;
use tokio::io::AsyncWriteExt;
use tokio_stream::StreamExt;
use std::error::Error;

/// Example 3: Stream Large File Encryption
pub async fn example_stream_large_file(master_key: Vec<u8>) -> Result<(), Box<dyn Error>> {
    println!("\n=== Example 3: Stream Large File Encryption ===");
    
    encrypt_large_file("/tmp/large_input.bin", "/tmp/large_output.enc", master_key).await?;
    
    Ok(())
}

/// Stream large file encryption
pub async fn encrypt_large_file(input_path: &str, output_path: &str, master_key: Vec<u8>) -> Result<(), Box<dyn Error>> {
    // Create large test file
    tokio::fs::write(input_path, b"Large file data...".repeat(10000)).await?;
    
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
    
    // Open files
    let input_file = File::open(input_path).await?;
    let mut output_file = File::create(output_path).await?;
    
    // Create file stream
    let file_stream = tokio_util::io::ReaderStream::new(input_file);
    
    // Stream encryption
    let mut encrypted_stream = Cipher::aes()
        .with_key(key)
        .on_chunk!(|chunk| {
            Ok => chunk,
            Err(e) => {
                log::error!("Encryption error: {}", e);
                return;
            }
        })
        .encrypt_stream(file_stream);
    
    // Process chunks
    let mut total_bytes = 0;
    while let Some(chunk) = encrypted_stream.next().await {
        total_bytes += chunk.len();
        output_file.write_all(&chunk).await?;
    }
    
    println!("Stream encrypted {} bytes from {} to {}", total_bytes, input_path, output_path);
    Ok(())
}