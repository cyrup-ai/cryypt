//! Test the fluent streaming compression API exactly as documented in README.md

use cryypt_compression::Compress;
use futures::StreamExt;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Testing Cryypt fluent streaming compression API...");

    let test_data = b"This is a larger test dataset for streaming compression that should be processed in chunks to demonstrate the on_chunk streaming capabilities of the fluent builder API";

    // Test streaming compression - README.md pattern with on_chunk
    let mut stream = Compress::zstd()
        .with_level(5)
        .on_chunk(|result| match result {
            Ok(compressed_chunk) => {
                println!("Compressed chunk: {} bytes", compressed_chunk.len());
                compressed_chunk
            }
            Err(e) => {
                eprintln!("Compression chunk failed: {}", e);
                panic!("Critical compression chunk failure")
            }
        })
        .compress(test_data);

    let mut total_compressed_size = 0;
    let mut compressed_chunks = Vec::new();

    while let Some(chunk) = stream.next().await {
        total_compressed_size += chunk.len();
        compressed_chunks.push(chunk);
        println!(
            "Received compressed chunk, total size so far: {}",
            total_compressed_size
        );
    }

    println!(
        "Streaming compression complete: {} bytes -> {} bytes",
        test_data.len(),
        total_compressed_size
    );

    // Combine all compressed chunks for decompression test
    let combined_compressed: Vec<u8> = compressed_chunks.into_iter().flatten().collect();

    // Test decompression (single result, not streaming - streaming decompression may not be implemented)
    let compressed_size = combined_compressed.len();
    let final_decompressed = Compress::zstd()
        .with_level(5)
        .on_result(|result| match result {
            Ok(decompressed_data) => {
                println!(
                    "Decompression successful: {} bytes",
                    decompressed_data.len()
                );
                decompressed_data
            }
            Err(e) => {
                eprintln!("Decompression failed: {}", e);
                panic!("Critical decompression failure")
            }
        })
        .decompress(combined_compressed)
        .await;

    println!(
        "Decompression complete: {} bytes -> {} bytes",
        compressed_size,
        final_decompressed.len()
    );
    if final_decompressed == test_data {
        println!("✅ Streaming round-trip successful - data matches original");
    } else {
        println!("❌ Streaming round-trip failed - data does not match");
        println!("Original: {} bytes", test_data.len());
        println!("Final: {} bytes", final_decompressed.len());
        return Err("Streaming round-trip verification failed".into());
    }

    Ok(())
}
