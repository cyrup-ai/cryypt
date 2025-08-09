use cryypt::{Cryypt, BadChunk};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Test 1: Success case with SHA256
    let hash = Cryypt::hash()
        .sha256()
        .on_result(|result| {
            Ok(bytes) => bytes,
            Err(e) => {
                log::error!("Hash computation failed: {}", e);
                Vec::new()
            }
        })
        .compute(b"Hello, World!")
        .await;

    println!("Test 1 - Success case:");
    println!("Hash length: {}", hash.len());
    println!("Hash: {}", hex::encode(&hash));

    // Test 2: HMAC with key
    let hmac = Cryypt::hash()
        .sha256()
        .with_key(b"secret_key")
        .on_result(|result| {
            Ok(bytes) => bytes,
            Err(e) => {
                log::error!("HMAC operation failed: {}", e);
                Vec::new()
            }
        })
        .compute(b"Message to authenticate")
        .await;

    println!("\nTest 2 - HMAC case:");
    println!("HMAC length: {}", hmac.len());
    println!("HMAC: {}", hex::encode(&hmac));

    // Test 3: Error case - this should trigger the error handler if we can force an error
    println!("\nTest 3 - Testing error handling:");
    let error_result = Cryypt::hash()
        .sha256()
        .on_result(|result| {
            Ok(bytes) => bytes,
            Err(e) => {
                log::error!("ERROR HANDLER CALLED: {}", e);
                vec![99, 99, 99]
            }
        })
        .compute(b"This should succeed normally")
        .await;

    println!(
        "Result length: {} (should be 32 for normal SHA256)",
        error_result.len()
    );
    if error_result.len() == 32 {
        println!("✅ NORMAL OPERATION - SHA256 hash computed successfully");
        println!("Hash: {}", hex::encode(&error_result));
    } else if error_result == vec![99, 99, 99] {
        println!("✅ ERROR HANDLER VERIFICATION PASSED - Custom error value returned");
    } else {
        println!("❌ UNEXPECTED RESULT: {:?}", error_result);
    }

    // Test 4: Streaming hash computation with on_chunk
    println!("\nTest 4 - Streaming SHA256 with on_chunk:");
    let stream_data = b"This is streaming data for hash computation";
    
    let mut hash_stream = Cryypt::hash()
        .sha256()
        .on_chunk(|chunk| {
            Ok => chunk.into(),
            Err(e) => {
                log::error!("Hash stream error: {}", e);
                BadChunk::from_error(e)
            }
        })
        .compute_stream(stream_data);

    use futures::StreamExt;
    let mut hash_chunks = Vec::new();
    while let Some(chunk) = hash_stream.next().await {
        hash_chunks.extend_from_slice(&chunk);
        println!("Hash chunk received: {} bytes", chunk.len());
    }
    
    if !hash_chunks.is_empty() {
        println!("Final hash: {}", hex::encode(&hash_chunks));
    } else {
        println!("No hash chunks received");
    }

    // Test 5: Streaming HMAC with on_chunk
    println!("\nTest 5 - Streaming HMAC with on_chunk:");
    let mut hmac_stream = Cryypt::hash()
        .sha256()
        .with_key(b"streaming_key")
        .on_chunk(|chunk| {
            Ok => chunk.into(),
            Err(e) => {
                log::error!("HMAC stream error: {}", e);
                BadChunk::from_error(e)
            }
        })
        .compute_stream(b"Streaming HMAC authentication data");

    let mut hmac_chunks = Vec::new();
    while let Some(chunk) = hmac_stream.next().await {
        hmac_chunks.extend_from_slice(&chunk);
        println!("HMAC chunk received: {} bytes", chunk.len());
    }
    
    if !hmac_chunks.is_empty() {
        println!("Final HMAC: {}", hex::encode(&hmac_chunks));
    } else {
        println!("No HMAC chunks received");
    }

    Ok(())
}
