use cryypt::Cryypt;
use futures::StreamExt;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Single Result Example - matches README.md exactly
    let key = b"test_key_32_bytes_long_for_aes!!".to_vec();

    let encrypted = Cryypt::cipher()
        .aes()
        .with_key(key.clone())
        .on_result(|result| match result {
            Ok(bytes) => bytes,
            Err(e) => {
                log::error!("Encryption failed: {}", e);
                panic!("Critical encryption failure")
            }
        })
        .encrypt(b"Secret message")
        .await; // Returns fully unwrapped value - no Result wrapper

    println!(
        "Single encryption - encrypted data length: {}",
        encrypted.len()
    );

    // Streaming Chunks Example - matches README.md exactly
    let large_data = b"This is large data that will be encrypted in chunks. ".repeat(1000);

    let mut stream = Cryypt::cipher()
        .aes()
        .with_key(key.clone())
        .on_chunk(|result| match result {
            Ok(encrypted_chunk) => {
                // Process each encrypted chunk as it arrives
                println!(
                    "Processing encrypted chunk: {} bytes",
                    encrypted_chunk.len()
                );
                encrypted_chunk
            }
            Err(e) => {
                log::error!("Chunk encryption failed: {}", e);
                panic!("Critical chunk encryption failure")
            }
        })
        .encrypt(large_data);

    while let Some(chunk) = stream.next().await {
        // Each chunk is already encrypted and ready to use
        println!("Received encrypted chunk: {} bytes", chunk.len());
    }

    println!("Streaming encryption completed");

    Ok(())
}
