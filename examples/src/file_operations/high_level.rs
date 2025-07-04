//! High-level file operations examples
//!
//! Demonstrates file encryption/decryption with various compression and encoding options.

use crate::file_operations::Key;
use cryypt::{Cryypt, KeyRetriever, FileKeyStore, on_result, on_chunk};
use std::error::Error;

/// Example 1: High-Level File Operations
pub async fn example_highlevel_file_ops(master_key: Vec<u8>) -> Result<(), Box<dyn Error>> {
    println!("\n=== Example 1: High-Level File Operations ===");
    
    // Retrieve key for file operations
    let store = FileKeyStore::at("/tmp/secure/keys").with_master_key(master_key);
    let key = KeyRetriever::new()
        .with_store(store)
        .with_namespace("my-app")
        .version(1)
        .retrieve(|result| {
            result.unwrap_or_else(|e| panic!("Operation error: {}", e))
        })
        .await; // Returns fully unwrapped value - no Result wrapper
    
    // Create test file
    tokio::fs::write("/tmp/document.pdf", b"PDF file content").await?;
    
    // Encrypt file with default zstd compression (saves as document.pdf.zst)
    Cryypt::cipher()
        .aes()
        .with_key(key.clone())
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("Operation error: {}", e))
        })
        .encrypt_file("/tmp/document.pdf")
        .await; // Returns fully unwrapped value - no Result wrapper
    
    println!("Encrypted file to /tmp/document.pdf.zst");
    
    // Decrypt file (saves as document.pdf)
    Cryypt::cipher()
        .aes()
        .with_key(key.clone())
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("Operation error: {}", e))
        })
        .decrypt_file("/tmp/document.pdf.zst")
        .await; // Returns fully unwrapped value - no Result wrapper
    
    println!("Decrypted file back to /tmp/document.pdf");
    
    // Create CSV file
    tokio::fs::write("/tmp/data.csv", b"name,value\ntest,123").await?;
    
    // Encrypt with specific compression (saves as data.csv.gz)
    Cryypt::cipher()
        .aes()
        .with_key(key.clone())
        .with_compression(Cryypt::compress().gzip().with_level(6))
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("Operation error: {}", e))
        })
        .encrypt_file("/tmp/data.csv")
        .await; // Returns fully unwrapped value - no Result wrapper
    
    println!("Encrypted CSV with gzip to /tmp/data.csv.gz");
    
    // Create text file
    tokio::fs::write("/tmp/message.txt", b"Secret message").await?;
    
    // Encrypt with base64 encoding (saves as message.txt.b64)
    Cryypt::cipher()
        .chacha20()
        .with_key(key.clone())
        .with_encoding("base64")
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("Operation error: {}", e))
        })
        .encrypt_file("/tmp/message.txt")
        .await; // Returns fully unwrapped value - no Result wrapper
    
    println!("Encrypted text with base64 to /tmp/message.txt.b64");
    
    // Create report file
    tokio::fs::write("/tmp/report.doc", b"Report content").await?;
    
    // Custom output path
    Cryypt::cipher()
        .aes()
        .with_key(key.clone())
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("Operation error: {}", e))
        })
        .encrypt_file("/tmp/report.doc")
        .save("/tmp/secure/report-backup.zst")
        .await; // Returns fully unwrapped value - no Result wrapper
    
    println!("Encrypted report to custom path /tmp/secure/report-backup.zst");
    
    // Create large file
    tokio::fs::write("/tmp/movie.mp4", b"Large video content...".repeat(1000)).await?;
    
    // Stream large files
    Cryypt::cipher()
        .aes()
        .with_key(key)
        .on_chunk!(|chunk| {
            Ok => chunk,
            Err(e) => {
                log::error!("Encryption error: {}", e);
                return;
            }
        })
        .encrypt_file_stream("/tmp/movie.mp4")
        .await; // Returns fully unwrapped value - no Result wrapper
    
    println!("Streamed encryption of large file");
    
    Ok(())
}