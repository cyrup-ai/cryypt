//! Compression API Examples - Exactly matching README.md patterns
//! These examples demonstrate Zstd, Gzip, Bzip2, and ZIP compression with fully unwrapped returns

use cryypt::{Cryypt, Compress, on_result, on_chunk};
use tokio_stream::{Stream, StreamExt};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    
    // Example 1: Zstandard (Recommended)
    example_zstd_compression().await?;
    
    // Example 2: Stream compression
    example_stream_compression().await?;
    
    // Example 3: Other compression formats
    example_other_formats().await?;
    
    // Example 4: ZIP archive
    example_zip_archive().await?;
    
    // Example 5: Direct builder
    example_direct_builder().await?;
    
    Ok(())
}

async fn example_zstd_compression() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n=== Example 1: Zstandard Compression ===");
    
    let data = b"Large text data that needs to be compressed...".repeat(100);
    
    // Compress data
    let compressed = Cryypt::compress()
        .zstd()
        .with_level(3)
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("Compression error: {}", e))
        })
        .compress(&data)
        .await; // Returns Vec<u8> - the compressed bytes, fully unwrapped
    
    println!("Original size: {} bytes", data.len());
    println!("Compressed size: {} bytes", compressed.len());
    println!("Compression ratio: {:.2}%", (compressed.len() as f64 / data.len() as f64) * 100.0);
    
    // Decompress
    let decompressed = Cryypt::compress()
        .zstd()
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("Decompression error: {}", e))
        })
        .decompress(&compressed)
        .await; // Returns Vec<u8> - the decompressed bytes, fully unwrapped
    
    println!("Decompressed size: {} bytes", decompressed.len());
    println!("Decompression successful: {}", data == decompressed);
    
    Ok(())
}

async fn example_stream_compression() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n=== Example 2: Stream compression ===");
    
    // Create input stream
    let chunks = vec![
        b"First chunk of data to compress".to_vec(),
        b"Second chunk of data to compress".to_vec(),
        b"Third chunk of data to compress".to_vec(),
    ];
    let input_stream = tokio_stream::iter(chunks.clone());
    
    // Stream compression
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
    let mut compressed_chunks = Vec::new();
    while let Some(chunk) = compressed_stream.next().await {
        // chunk is Vec<u8> - compressed bytes ready to write
        println!("Compressed chunk: {} bytes", chunk.len());
        compressed_chunks.push(chunk);
    }
    
    // Stream decompression
    let compressed_input = tokio_stream::iter(compressed_chunks);
    let mut decompressed_stream = Cryypt::compress()
        .zstd()
        .on_chunk!(|chunk| {
            Ok => chunk,
            Err(e) => {
                log::error!("Decompression error: {}", e);
                return;
            }
        })
        .decompress_stream(compressed_input);
    
    // Process decompressed chunks
    println!("\nDecompressed chunks:");
    while let Some(chunk) = decompressed_stream.next().await {
        println!("  {}", String::from_utf8_lossy(&chunk));
    }
    
    Ok(())
}

async fn example_other_formats() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n=== Example 3: Other compression formats ===");
    
    let data = b"Data to compress with different algorithms";
    
    // Gzip
    let compressed = Cryypt::compress()
        .gzip()
        .with_level(6)
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("Compression error: {}", e))
        })
        .compress(data)
        .await; // Returns fully unwrapped value - no Result wrapper
    
    println!("Gzip compressed: {} bytes", compressed.len());
    
    // Bzip2
    let compressed = Cryypt::compress()
        .bzip2()
        .with_level(9)
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("Operation error: {}", e))
        })
        .compress(data)
        .await; // Returns fully unwrapped value - no Result wrapper
    
    println!("Bzip2 compressed: {} bytes", compressed.len());
    
    Ok(())
}

async fn example_zip_archive() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n=== Example 4: ZIP archive ===");
    
    let readme_data = b"This is the README content";
    let json_data = b"{\"name\": \"example\", \"version\": \"1.0\"}";
    
    // ZIP archive
    let archive = Cryypt::compress()
        .zip()
        .add_file("readme.txt", readme_data)
        .add_file("data.json", json_data)
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("Operation error: {}", e))
        })
        .compress()
        .await; // Returns Vec<u8> - the ZIP archive bytes, fully unwrapped
    
    println!("ZIP archive created: {} bytes", archive.len());
    
    Ok(())
}

async fn example_direct_builder() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n=== Example 5: Direct builder API ===");
    
    let data = b"Data to compress with direct builder";
    
    // Alternative: Direct builders work too
    let compressed = Compress::zstd()
        .with_level(3)
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("Operation error: {}", e))
        })
        .compress(data)
        .await; // Returns fully unwrapped value - no Result wrapper
    
    println!("Direct builder compressed: {} bytes", compressed.len());
    
    Ok(())
}