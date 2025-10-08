use cryypt::Cryypt;
use futures::StreamExt;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Single Result Example - matches README.md exactly
    let hash: Vec<u8> = Cryypt::hash()
        .sha256()
        .on_result(|result| match result {
            Ok(bytes) => bytes.into(),
            Err(e) => {
                log::error!("Hash computation failed: {}", e);
                panic!("Critical hash failure")
            }
        })
        .compute(b"Hello, World!")
        .await; // Returns Vec<u8> - the actual hash bytes, fully unwrapped

    println!("Single hash - hash length: {}", hash.len());

    // Streaming Hash Computation Example - matches README.md exactly
    let large_file_data = b"This is large file data for streaming hash computation. ".repeat(1000);

    let mut stream = Cryypt::hash()
        .blake3()
        .on_chunk(|result| match result {
            Ok(hash_chunk) => {
                // Process incremental hash state
                println!("Hash progress update");
                hash_chunk
            }
            Err(e) => {
                log::error!("Hash chunk failed: {}", e);
                panic!("Critical hash chunk failure")
            }
        })
        .compute_stream(&large_file_data);

    while let Some(chunk) = stream.next().await {
        // Each chunk represents incremental hash progress
        println!("Hash progress: {} bytes processed", chunk.len());
    }

    println!("Streaming hash computation completed");

    Ok(())
}
