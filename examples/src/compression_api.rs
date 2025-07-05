//! Compression API examples - EXACTLY matching compression/README.md

use cryypt::{Cryypt, on_result, Compress, FileKeyStore, KeyRetriever, Cipher};
use std::path::Path;

/// Zstandard compression example from README
async fn zstandard_example() -> Result<(), Box<dyn std::error::Error>> {
    // Compress data
    let compressed = Cryypt::compress()
        .zstd()
        .with_level(3)
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("Compression error: {}", e))
        })
        .compress(b"Large text data...")
        .await; // Returns fully unwrapped value - no Result wrapper // Returns Vec<u8> - the compressed bytes, fully unwrapped

    // Decompress
    let decompressed = Cryypt::compress()
        .zstd()
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("Decompression error: {}", e))
        })
        .decompress(&compressed)
        .await; // Returns fully unwrapped value - no Result wrapper // Returns Vec<u8> - the decompressed bytes, fully unwrapped

    println!("Decompressed: {:?}", String::from_utf8(decompressed)?);

    // Stream compression
    let input_stream = tokio_stream::iter(vec![
        Ok(b"Part 1".to_vec()),
        Ok(b"Part 2".to_vec()),
        Ok(b"Part 3".to_vec()),
    ]);
    
    let mut compressed_stream = Cryypt::compress()
        .zstd()
        .with_level(6)
        .on_chunk!(|chunk| {
            Ok => chunk,  // Unwrapped compressed bytes
            Err(e) => {
                log::error!("Compression error: {}", e);
                return;
            }
        })
        .compress_stream(input_stream); // Returns Stream<Item = Vec<u8>> - fully unwrapped compressed chunks

    // Process compressed chunks
    let mut output = Vec::new();
    while let Some(chunk) = compressed_stream.next().await {
        // chunk is Vec<u8> - compressed bytes ready to write
        output.extend_from_slice(&chunk);
    }

    Ok(())
}

/// Other compression formats example from README
async fn other_formats_example() -> Result<(), Box<dyn std::error::Error>> {
    let data = b"Test data for compression";
    
    // Gzip
    let compressed = Cryypt::compress()
        .gzip()
        .with_level(6)
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("Compression error: {}", e))
        })
        .compress(data)
        .await; // Returns fully unwrapped value - no Result wrapper

    // Bzip2
    let compressed = Cryypt::compress()
        .bzip2()
        .with_level(9)
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("Operation error: {}", e))
        })
        .compress(data)
        .await; // Returns fully unwrapped value - no Result wrapper

    // ZIP archive
    let readme_data = b"This is the readme";
    let json_data = b"{\"test\": true}";
    
    let archive = Cryypt::compress()
        .zip()
        .add_file("readme.txt", readme_data)
        .add_file("data.json", json_data)
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("Operation error: {}", e))
        })
        .compress()
        .await; // Returns Vec<u8> - the ZIP archive bytes, fully unwrapped

    // Alternative: Direct builders work too
    let compressed = Compress::zstd()
        .with_level(3)
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("Operation error: {}", e))
        })
        .compress(data)
        .await; // Returns fully unwrapped value - no Result wrapper

    println!("All compression formats tested successfully");
    Ok(())
}

/// Batch Compress and Encrypt Files example from README
async fn compress_and_encrypt_files(
    files: Vec<&str>,
    output_archive: &str
) -> Result<(), Box<dyn std::error::Error>> {
    let master_key = [0u8; 32];
    
    // Retrieve key
    let store = FileKeyStore::at("/secure/keys").with_master_key(master_key);
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
    
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Zstandard Compression ===");
    zstandard_example().await?;
    
    println!("\n=== Other Compression Formats ===");
    other_formats_example().await?;
    
    // Create test files for batch example
    tokio::fs::write("/tmp/test1.txt", b"Test file 1").await?;
    tokio::fs::write("/tmp/test2.txt", b"Test file 2").await?;
    
    println!("\n=== Batch Compress and Encrypt ===");
    compress_and_encrypt_files(
        vec!["/tmp/test1.txt", "/tmp/test2.txt"],
        "/tmp/encrypted_archive.zip.enc"
    ).await?;
    
    Ok(())
}