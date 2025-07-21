use cryypt::Cryypt;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Test 1: Success case with valid key
    let key = b"test_key_32_bytes_long_for_aes!!".to_vec(); // Exactly 32 bytes

    let encrypted = Cryypt::cipher()
        .aes()
        .with_key(key.clone())
        .on_result(|result| {
            match result {
                Ok(result) => result,
                Err(e) => {
                    log::error!("Cipher operation failed: {}", e);
                    Vec::new()
                }
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
            match result {
                Ok(result) => result,
                Err(e) => {
                    log::error!("Cipher operation failed: {}", e);
                    Vec::new()
                }
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
            match result {
                Ok(result) => result,
                Err(e) => {
                    log::error!("ERROR HANDLER CALLED: {}", e);
                    vec![42, 42, 42] // Return specific error value to prove handler was used
                }
            }
        })
        .encrypt(b"This should fail")
        .await;
    
    println!("Error result length: {} (should be 3 if error handler worked)", error_result.len());
    if error_result == vec![42, 42, 42] {
        println!("✅ ERROR HANDLER VERIFICATION PASSED - Custom error value returned");
    } else {
        println!("❌ ERROR HANDLER VERIFICATION FAILED - Expected [42, 42, 42], got {:?}", error_result);
    }

    Ok(())
}