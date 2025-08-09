use cryypt::{Cipher, Compress, Cryypt, FileKeyStore, KeyRetriever, BadChunk};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Sample data for compression
    let large_data = b"This is some large text data that we want to compress. ".repeat(100);

    // Compress data with Zstd
    let data_for_closure = large_data.clone();
    let compressed = Cryypt::compress()
        .zstd()
        .with_level(3)
        .on_result(move |result| {
            Ok(bytes) => bytes,
            Err(e) => {
                log::error!("Compression error: {}", e);
                data_for_closure.clone()
            }
        })
        .compress(large_data.clone())
        .await; // Returns Vec<u8> - the compressed bytes, fully unwrapped

    println!("Original data size: {} bytes", large_data.len());
    println!("Compressed size: {} bytes", compressed.len());
    println!(
        "Compression ratio: {:.2}%",
        (compressed.len() as f64 / large_data.len() as f64) * 100.0
    );

    // Decompress
    let decompressed = Cryypt::compress()
        .zstd()
        .on_result(move |result| {
            Ok(bytes) => bytes,
            Err(e) => {
                log::error!("Decompression failed: {}", e);
                Vec::new()
            }
        })
        .decompress(compressed.clone())
        .await; // Returns Vec<u8> - the decompressed bytes, fully unwrapped

    println!("Decompressed size: {} bytes", decompressed.len());
    println!(
        "Data integrity: {}",
        if decompressed == large_data {
            "✅ PASSED"
        } else {
            "❌ FAILED"
        }
    );

    // Test different compression algorithms

    // Gzip
    let data_for_gzip_closure = large_data.clone();
    let gzip_compressed = Cryypt::compress()
        .gzip()
        .with_level(6)
        .on_result(move |result| {
            Ok(bytes) => bytes,
            Err(e) => {
                log::error!("Gzip compression error: {}", e);
                data_for_gzip_closure.clone()
            }
        })
        .compress(large_data.clone())
        .await; // Returns fully unwrapped value - no Result wrapper

    println!("Gzip compressed size: {} bytes", gzip_compressed.len());

    // // Bzip2 (disabled - feature not enabled)
    // let bzip2_compressed = Cryypt::compress()
    //     .bzip2()
    //     .with_level(9)
    //     .on_result(|result| {
    //         Ok(result) => result.to_vec(),
    //         Err(e) => {
    //             log::error!("Bzip2 compression error: {}", e);
    //             Vec::new()
    //         }
    //     })
    //     .compress(large_data.clone())
    //     .await; // Returns fully unwrapped value - no Result wrapper

    // println!("Bzip2 compressed size: {} bytes", bzip2_compressed.len());

    // // ZIP archive with multiple files (disabled - feature not enabled)
    // let readme_data = b"This is a README file";
    // let json_data = br#"{"name": "example", "version": "1.0.0"}"#;

    // let archive = Cryypt::compress()
    //     .zip()
    //     .add_file("readme.txt", readme_data)
    //     .add_file("data.json", json_data)
    //     .on_result(|result| {
    //         Ok(result) => result.to_vec(),
    //         Err(e) => {
    //             log::error!("ZIP operation error: {}", e);
    //             Vec::new()
    //         }
    //     })
    //     .compress()
    //     .await; // Returns Vec<u8> - the ZIP archive bytes, fully unwrapped

    // println!("ZIP archive size: {} bytes", archive.len());

    // Alternative: Direct builders work too
    let direct_compressed = Compress::zstd()
        .with_level(3)
        .on_result(move |result| {
            Ok(bytes) => bytes,
            Err(e) => {
                log::error!("Direct compression error: {}", e);
                Vec::new()
            }
        })
        .compress(large_data.clone())
        .await; // Returns fully unwrapped value - no Result wrapper

    println!(
        "Direct builder compressed size: {} bytes",
        direct_compressed.len()
    );

    // Test streaming compression with on_chunk
    println!("\nStreaming compression with on_chunk:");
    let stream_data = b"This is streaming data that will be compressed in chunks";
    
    let mut compressed_stream = Cryypt::compression()
        .zstd()
        .with_level(3)
        .on_chunk(|chunk| {
            Ok => chunk.into(),
            Err(e) => {
                log::error!("Compression stream error: {}", e);
                BadChunk::from_error(e)
            }
        })
        .compress_stream(stream_data);

    use futures::StreamExt;
    let mut compressed_chunks = Vec::new();
    while let Some(chunk) = compressed_stream.next().await {
        compressed_chunks.extend_from_slice(&chunk);
        println!("Compressed chunk received: {} bytes", chunk.len());
    }
    println!("Total compressed stream size: {} bytes", compressed_chunks.len());

    // Test streaming decompression with on_chunk
    println!("\nStreaming decompression with on_chunk:");
    let mut decompressed_stream = Cryypt::compression()
        .zstd()
        .on_chunk(|chunk| {
            Ok => chunk.into(),
            Err(e) => {
                log::error!("Decompression stream error: {}", e);
                BadChunk::from_error(e)
            }
        })
        .decompress_stream(compressed_chunks);

    let mut decompressed_chunks = Vec::new();
    while let Some(chunk) = decompressed_stream.next().await {
        decompressed_chunks.extend_from_slice(&chunk);
        println!("Decompressed chunk received: {} bytes", chunk.len());
    }
    println!("Decompressed stream: {}", String::from_utf8_lossy(&decompressed_chunks));

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
        .on_result(move |result| {
            Ok(key) => key,
            Err(e) => {
                log::error!("Key retrieval failed: {}", e);
                Vec::new()
            }
        })
        .retrieve("compression-demo-key")
        .await; // Returns fully unwrapped value - no Result wrapper

    // First compress the data
    let compressed = Compress::zstd()
        .with_level(6)
        .on_result(move |result| {
            Ok(bytes) => bytes,
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
        .on_result(move |result| {
            Ok(bytes) => bytes,
            Err(e) => {
                log::error!("Encryption failed: {}", e);
                Vec::new()
            }
        })
        .encrypt(compressed.clone())
        .await; // Returns fully unwrapped value - no Result wrapper

    println!("Compress + Encrypt demo:");
    println!("  Original: {} bytes", sample_data.len());
    println!("  Compressed: {} bytes", compressed.len());
    println!("  Encrypted: {} bytes", encrypted.len());

    Ok(())
}
