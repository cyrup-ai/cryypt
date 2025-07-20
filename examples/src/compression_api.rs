use cryypt::{Cryypt, Compress, Cipher, on_result, FileKeyStore, KeyRetriever};
use std::path::Path;
use tokio::io::AsyncWriteExt;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Sample data for compression
    let large_data = b"This is some large text data that we want to compress. ".repeat(100);
    
    // Compress data with Zstd
    let compressed = Cryypt::compress()
        .zstd()
        .with_level(3)
        .on_result(|result| {
            match result {
                Ok(result) => result.to_vec(),
                Err(e) => {
                    log::error!("Compression error: {}", e);
                    large_data.clone()
                }
            }
        })
        .compress(&large_data)
        .await; // Returns Vec<u8> - the compressed bytes, fully unwrapped

    println!("Original data size: {} bytes", large_data.len());
    println!("Compressed size: {} bytes", compressed.len());
    println!("Compression ratio: {:.2}%", (compressed.len() as f64 / large_data.len() as f64) * 100.0);

    // Decompress
    let decompressed = Cryypt::compress()
        .zstd()
        .on_result(|result| {
            match result {
                Ok(result) => result.to_vec(),
                Err(e) => {
                    log::error!("Decompression failed: {}", e);
                    Vec::new()
                }
            }
        })
        .decompress(&compressed)
        .await; // Returns Vec<u8> - the decompressed bytes, fully unwrapped

    println!("Decompressed size: {} bytes", decompressed.len());
    println!("Data integrity: {}", if decompressed == large_data { "✅ PASSED" } else { "❌ FAILED" });

    // Test different compression algorithms
    
    // Gzip
    let gzip_compressed = Cryypt::compress()
        .gzip()
        .with_level(6)
        .on_result(|result| {
            match result {
                Ok(result) => result.to_vec(),
                Err(e) => {
                    log::error!("Gzip compression error: {}", e);
                    large_data.clone()
                }
            }
        })
        .compress(&large_data)
        .await; // Returns fully unwrapped value - no Result wrapper

    println!("Gzip compressed size: {} bytes", gzip_compressed.len());

    // Bzip2
    let bzip2_compressed = Cryypt::compress()
        .bzip2()
        .with_level(9)
        .on_result(|result| {
            Ok => result.to_vec(),
            Err(e) => {
                log::error!("Bzip2 compression error: {}", e);
                Vec::new()
            }
        })
        .compress(&large_data)
        .await; // Returns fully unwrapped value - no Result wrapper

    println!("Bzip2 compressed size: {} bytes", bzip2_compressed.len());

    // ZIP archive with multiple files
    let readme_data = b"This is a README file";
    let json_data = br#"{"name": "example", "version": "1.0.0"}"#;
    
    let archive = Cryypt::compress()
        .zip()
        .add_file("readme.txt", readme_data)
        .add_file("data.json", json_data)
        .on_result(|result| {
            Ok => result.to_vec(),
            Err(e) => {
                log::error!("ZIP operation error: {}", e);
                Vec::new()
            }
        })
        .compress()
        .await; // Returns Vec<u8> - the ZIP archive bytes, fully unwrapped

    println!("ZIP archive size: {} bytes", archive.len());

    // Alternative: Direct builders work too
    let direct_compressed = Compress::zstd()
        .with_level(3)
        .on_result(|result| {
            Ok => result.to_vec(),
            Err(e) => {
                log::error!("Direct compression error: {}", e);
                Vec::new()
            }
        })
        .compress(&large_data)
        .await; // Returns fully unwrapped value - no Result wrapper

    println!("Direct builder compressed size: {} bytes", direct_compressed.len());

    // Demonstrate combined compression and encryption
    compress_and_encrypt_demo().await?;

    Ok(())
}

async fn compress_and_encrypt_demo() -> Result<(), Box<dyn std::error::Error>> {
    let sample_data = b"Sensitive data that needs both compression and encryption";
    
    // Setup master key and store
    let master_key = [1u8; 32]; // In production, generate securely
    let store = FileKeyStore::at("/tmp/compression_keys").with_master_key(master_key);
    
    // Generate a key for encryption
    let key = KeyRetriever::new()
        .with_store(store)
        .with_namespace("compression-demo")
        .version(1)
        .on_result(|result| {
            Ok => result,
            Err(e) => {
                log::error!("Key retrieval failed: {}", e);
                Vec::new()
            }
        })
        .retrieve()
        .await; // Returns fully unwrapped value - no Result wrapper
    
    // First compress the data
    let compressed = Compress::zstd()
        .with_level(6)
        .on_result(|result| {
            Ok => result.to_vec(),
            Err(e) => {
                log::error!("Compression failed: {}", e);
                sample_data.to_vec()
            }
        })
        .compress(sample_data)
        .await; // Returns fully unwrapped value - no Result wrapper
    
    // Then encrypt the compressed data
    let encrypted = Cipher::aes()
        .with_key(key)
        .on_result(|result| {
            match result {
                Ok(result) => result.to_vec(),
                Err(e) => {
                    log::error!("Encryption failed: {}", e);
                    compressed.clone()
                }
            }
        })
        .encrypt(&compressed)
        .await; // Returns fully unwrapped value - no Result wrapper
    
    println!("Compress + Encrypt demo:");
    println!("  Original: {} bytes", sample_data.len());
    println!("  Compressed: {} bytes", compressed.len());
    println!("  Encrypted: {} bytes", encrypted.len());
    
    Ok(())
}