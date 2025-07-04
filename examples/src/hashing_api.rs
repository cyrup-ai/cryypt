//! Hashing API Examples - Exactly matching README.md patterns
//! These examples demonstrate SHA-256, SHA3, and BLAKE2b hashing with fully unwrapped returns

use cryypt::{Cryypt, Hash, on_result, on_chunk};
use tokio_stream::{Stream, StreamExt};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    
    // Example 1: SHA-256 Hashing
    example_sha256_hashing().await?;
    
    // Example 2: Stream hashing
    example_stream_hashing().await?;
    
    // Example 3: HMAC with key
    example_hmac().await?;
    
    // Example 4: SHA3 and BLAKE2b
    example_sha3_blake2b().await?;
    
    // Example 5: Direct builder
    example_direct_builder().await?;
    
    Ok(())
}

async fn example_sha256_hashing() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n=== Example 1: SHA-256 Hashing ===");
    
    // Simple hash
    let hash = Cryypt::hash()
        .sha256()
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("Hash error: {}", e))
        })
        .compute(b"Hello, World!")
        .await; // Returns Vec<u8> - the actual hash bytes, fully unwrapped
    
    println!("Hash: {} bytes - {:?}", hash.len(), &hash[..8]);
    
    // Hash entire file at once (Future)
    let file_data = b"This is the content of a file that we want to hash";
    let hash = Cryypt::hash()
        .sha256()
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("Hash error: {}", e))
        })
        .compute(&file_data)
        .await; // Returns Vec<u8> - the actual hash bytes, fully unwrapped
    
    println!("File hash: {} bytes - {:?}", hash.len(), &hash[..8]);
    
    Ok(())
}

async fn example_stream_hashing() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n=== Example 2: Stream hashing ===");
    
    // Create a sample file stream
    let file_chunks = vec![
        b"First chunk of data".to_vec(),
        b"Second chunk of data".to_vec(),
        b"Third chunk of data".to_vec(),
    ];
    let file_stream = tokio_stream::iter(file_chunks);
    
    // Stream hashing
    let mut hash_stream = Cryypt::hash()
        .sha256()
        .on_chunk!(|chunk| {
            Ok => chunk,
            Err(e) => {
                log::error!("Hash chunk error: {}", e);
                return;
            }
        })
        .compute_stream(file_stream); // Returns Stream<Item = Vec<u8>> - fully unwrapped hash chunks
    
    // Process the hash stream
    let mut last_hash = Vec::new();
    while let Some(partial_hash) = hash_stream.next().await {
        // partial_hash is Vec<u8> - the hash bytes at this point in the stream
        println!("Hash update: {} bytes - {:?}", partial_hash.len(), &partial_hash[..8]);
        last_hash = partial_hash;
    }
    
    println!("Final hash: {} bytes", last_hash.len());
    
    Ok(())
}

async fn example_hmac() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n=== Example 3: HMAC with key ===");
    
    // HMAC with key
    let hmac = Cryypt::hash()
        .sha256()
        .with_key(b"secret_key")
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("Operation error: {}", e))
        })
        .compute(b"Message")
        .await; // Returns fully unwrapped value - no Result wrapper
    
    println!("HMAC: {} bytes - {:?}", hmac.len(), &hmac[..8]);
    
    Ok(())
}

async fn example_sha3_blake2b() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n=== Example 4: SHA3 and BLAKE2b ===");
    
    // SHA3-256
    let hash = Cryypt::hash()
        .sha3_256()
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("Operation error: {}", e))
        })
        .compute(b"Hello, World!")
        .await; // Returns fully unwrapped value - no Result wrapper
    
    println!("SHA3-256: {} bytes - {:?}", hash.len(), &hash[..8]);
    
    // SHA3-512 with custom handling
    let hash = Cryypt::hash()
        .sha3_512()
        .on_result!(|result| {
            result.map(|hash| {
                println!("Hash computed: {:?}", &hash[..8]);
                hash
            }).unwrap_or_else(|e| panic!("Hash error: {}", e))
        })
        .compute(b"Hello, World!")
        .await; // Returns fully unwrapped value - no Result wrapper
    
    println!("SHA3-512: {} bytes", hash.len());
    
    // BLAKE2b with output size
    let hash = Cryypt::hash()
        .blake2b()
        .with_output_size(32) // 32 bytes
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("Operation error: {}", e))
        })
        .compute(b"Hello, World!")
        .await; // Returns fully unwrapped value - no Result wrapper
    
    println!("BLAKE2b: {} bytes - {:?}", hash.len(), &hash[..8]);
    
    Ok(())
}

async fn example_direct_builder() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n=== Example 5: Direct builder API ===");
    
    // Alternative: Direct builder is also available
    let hash = Hash::sha256()
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("Operation error: {}", e))
        })
        .compute(b"Direct builder example")
        .await; // Returns fully unwrapped value - no Result wrapper
    
    println!("Direct builder hash: {} bytes - {:?}", hash.len(), &hash[..8]);
    
    Ok(())
}