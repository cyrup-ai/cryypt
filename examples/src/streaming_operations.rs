//! Streaming Operations Examples - Exactly matching README.md patterns
//! These examples demonstrate streaming vs future patterns

use cryypt::{Hash, Cipher, Compress, FileKeyStore, on_result, on_chunk};
use tokio_stream::{Stream, StreamExt};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    
    // Create a master key for the key store
    let master_key = vec![0u8; 32]; // In production, use a secure master key
    
    // Example 1: Future vs Streaming patterns
    example_future_vs_streaming().await?;
    
    // Example 2: Complete streaming pipeline
    example_streaming_pipeline(master_key).await?;
    
    Ok(())
}

async fn example_future_vs_streaming() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n=== Future vs Streaming Patterns ===");
    
    let data = b"Data to process";
    
    // FUTURE PATTERN: Single operation returning Future<Output = Result<T>>
    // on_result! handles Result<T> and returns Result<T>
    let hash = Hash::sha256()
        .on_result!(|result| {
            Ok => Ok(result),    // Pass through success
            Err(e) => Err(e)     // Pass through or transform error
        })
        .compute(data)
        .await; // Returns fully unwrapped value - no Result wrapper  // Await the Future
    
    println!("Future pattern hash: {} bytes", hash.len());
    
    // STREAMING PATTERN: Operations returning Stream<Item = T>
    // on_chunk! unwraps each Result<chunk> to give you chunk directly
    let file_chunks = vec![
        b"Chunk 1".to_vec(),
        b"Chunk 2".to_vec(),
        b"Chunk 3".to_vec(),
    ];
    let file_stream = tokio_stream::iter(file_chunks);
    
    let mut hash_stream = Hash::sha256()
        .on_chunk!(|chunk| {
            Ok => chunk,         // Returns T (unwrapped chunk data)
            Err(e) => {
                log::error!("Chunk error: {}", e);
                return;          // Skip bad chunk
            }
        })
        .compute_stream(file_stream);  // Returns Stream, not Future
    
    // Process unwrapped chunks from the Stream
    println!("\nStreaming pattern hash updates:");
    while let Some(chunk) = hash_stream.next().await {
        // chunk is already unwrapped by on_chunk!
        println!("  Hash update: {} bytes", chunk.len());
    }
    
    Ok(())
}

async fn example_streaming_pipeline(master_key: Vec<u8>) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n=== Complete Streaming Pipeline ===");
    
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
    
    // Create initial file stream
    let file_chunks = vec![
        b"First chunk of file data".to_vec(),
        b"Second chunk of file data".to_vec(),
        b"Third chunk of file data".to_vec(),
    ];
    let file_stream = tokio_stream::iter(file_chunks);
    
    // Complete streaming pipeline example
    let mut pipeline = file_stream
        .on_chunk!(|chunk| {
            Ok => chunk,
            Err(e) => {
                log::error!("File read error: {}", e);
                return;
            }
        });
    
    let compressed = Compress::zstd()
        .with_level(3)
        .on_chunk!(|chunk| {
            Ok => chunk,
            Err(e) => return
        })
        .compress_stream(pipeline);
    
    let encrypted = Cipher::aes()
        .with_key(key)
        .on_chunk!(|chunk| {
            Ok => chunk,
            Err(e) => return
        })
        .encrypt_stream(compressed);
    
    let hash = Hash::sha256()
        .on_chunk!(|chunk| {
            Ok => chunk,
            Err(e) => return
        })
        .compute_stream(encrypted);
    
    // All chunks are unwrapped at each stage
    println!("Processing pipeline (compress -> encrypt -> hash):");
    let mut chunk_count = 0;
    hash.for_each(|hash_update| {
        chunk_count += 1;
        println!("  Chunk {}: hash update {} bytes", chunk_count, hash_update.len());
        async {}
    }).await;
    
    println!("Pipeline complete: processed {} chunks", chunk_count);
    
    Ok(())
}