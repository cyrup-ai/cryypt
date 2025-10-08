use cryypt::Cryypt;
use futures::StreamExt;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Single Result Example - matches README.md exactly
    let compressed = Cryypt::compress()
        .zstd()
        .with_level(3)
        .on_result(|result| match result {
            Ok(bytes) => bytes,
            Err(e) => {
                log::error!("Compression failed: {}", e);
                panic!("Critical compression failure")
            }
        })
        .compress(b"Large text data...")
        .await; // Returns Vec<u8> - the compressed bytes, fully unwrapped

    println!(
        "Single compression - compressed data length: {}",
        compressed.len()
    );

    // Streaming Compression Example - matches README.md exactly
    let massive_dataset = b"This is massive data that will be compressed in chunks. ".repeat(1000);

    let mut stream = Cryypt::compress()
        .zstd()
        .with_level(5)
        .on_chunk(|result| match result {
            Ok(compressed_chunk) => {
                // Stream compressed chunks to storage
                println!(
                    "Writing compressed chunk to archive: {} bytes",
                    compressed_chunk.len()
                );
                compressed_chunk
            }
            Err(e) => {
                log::error!("Compression chunk failed: {}", e);
                panic!("Critical compression chunk failure")
            }
        })
        .compress(massive_dataset);

    let mut total_compressed_size = 0;
    while let Some(chunk) = stream.next().await {
        // Each chunk is compressed and ready for storage
        total_compressed_size += chunk.len();
        println!("Received compressed chunk: {} bytes", chunk.len());
    }

    println!(
        "Streaming compression completed - total size: {} bytes",
        total_compressed_size
    );

    Ok(())
}
