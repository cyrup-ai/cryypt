use cryypt::{Cryypt, BadChunk};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Test 1: Success case with valid key
    let key = b"test_key_32_bytes_long_for_aes!!".to_vec(); // Exactly 32 bytes

    let encrypted = Cryypt::cipher()
        .aes()
        .with_key(key.clone())
        .on_result(|result| {
            Ok(bytes) => bytes,
            Err(e) => {
                log::error!("Encryption error: {}", e);
                Vec::new()
            }
        })
        .encrypt(b"Secret message")
        .await;

    println!("Test 1 - Success case:");
    println!("Encrypted data length: {}", encrypted.len());

    let plaintext = Cryypt::cipher()
        .aes()
        .with_key(key)
        .on_result(|result| {
            Ok(bytes) => bytes,
            Err(e) => {
                log::error!("Encryption error: {}", e);
                Vec::new()
            }
        })
        .decrypt(encrypted.clone())
        .await;

    println!("Decrypted: {}", String::from_utf8_lossy(&plaintext));

    // Test 2: Error case with invalid key size - this should trigger the error handler
    println!("\nTest 2 - Error case with invalid key:");
    let invalid_key = b"short_key".to_vec(); // Only 9 bytes, should fail

    let error_result = Cryypt::cipher()
        .aes()
        .with_key(invalid_key)
        .on_result(|result| {
            Ok(bytes) => bytes,
            Err(e) => {
                log::error!("Encryption error: {}", e);
                Vec::new()
            }
        })
        .encrypt(b"This should fail")
        .await;

    println!(
        "Error result length: {} (should be 3 if error handler worked)",
        error_result.len()
    );
    if error_result == vec![42, 42, 42] {
        println!("✅ ERROR HANDLER VERIFICATION PASSED - Custom error value returned");
    } else {
        println!(
            "❌ ERROR HANDLER VERIFICATION FAILED - Expected [42, 42, 42], got {:?}",
            error_result
        );
    }

    // Test 3: Streaming encryption with on_chunk
    println!("\nTest 3 - Streaming encryption with on_chunk:");
    let stream_key = b"stream_key_32_bytes_long_for_aes!".to_vec();
    
    let mut stream_encrypted = Cryypt::cipher()
        .aes()
        .with_key(stream_key.clone())
        .on_chunk(|chunk| {
            Ok => chunk.into(),
            Err(e) => {
                log::error!("Stream encryption error: {}", e);
                BadChunk::from_error(e)
            }
        })
        .encrypt_stream(b"Streaming secret message");
    
    use futures::StreamExt;
    let mut encrypted_chunks = Vec::new();
    while let Some(chunk) = stream_encrypted.next().await {
        encrypted_chunks.extend_from_slice(&chunk);
        println!("Received encrypted chunk of {} bytes", chunk.len());
    }
    
    println!("Total encrypted stream data: {} bytes", encrypted_chunks.len());

    // Test 4: Streaming decryption with on_chunk
    println!("\nTest 4 - Streaming decryption with on_chunk:");
    let mut stream_decrypted = Cryypt::cipher()
        .aes()  
        .with_key(stream_key)
        .on_chunk(|chunk| {
            Ok => chunk.into(),
            Err(e) => {
                log::error!("Stream decryption error: {}", e);
                BadChunk::from_error(e)
            }
        })
        .decrypt_stream(encrypted_chunks);
    
    let mut decrypted_chunks = Vec::new(); 
    while let Some(chunk) = stream_decrypted.next().await {
        decrypted_chunks.extend_from_slice(&chunk);
        println!("Received decrypted chunk of {} bytes", chunk.len());
    }
    
    println!("Decrypted stream: {}", String::from_utf8_lossy(&decrypted_chunks));

    Ok(())
}
