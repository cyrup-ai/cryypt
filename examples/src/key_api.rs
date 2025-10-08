use cryypt::Cryypt;
use futures::StreamExt;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Single Key Generation Example - matches README.md exactly
    let key: Vec<u8> = Cryypt::key()
        .aes()
        .with_size(256)
        .on_result(|result| match result {
            Ok(key_bytes) => key_bytes,
            Err(e) => {
                log::error!("Key generation failed: {}", e);
                panic!("Critical key generation failure")
            }
        })
        .generate()
        .await;

    println!("Single key generation - key length: {}", key.len());

    // Batch Key Generation Example - matches README.md exactly
    let mut stream = Cryypt::key()
        .rsa()
        .with_size(4096)
        .on_chunk(|result| match result {
            Ok(keypair_chunk) => {
                // Store each generated keypair
                println!("Storing keypair securely: {} bytes", keypair_chunk.len());
                keypair_chunk
            }
            Err(e) => {
                log::error!("Keypair generation failed: {}", e);
                panic!("Critical keypair generation failure")
            }
        })
        .generate_batch(100); // Generate 100 keypairs

    while let Some(keypair) = stream.next().await {
        println!("Generated keypair {}", keypair.len());
    }

    println!("Batch key generation completed");

    Ok(())
}
