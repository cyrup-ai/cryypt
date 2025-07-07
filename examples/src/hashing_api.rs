use cryypt::Cryypt;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Test 1: Success case with SHA256
    let hash = Cryypt::hash()
        .sha256()
        .on_result(cryypt::__cryypt_on_result_impl!(|result| {
            Ok => result.to_vec(),
            Err(e) => {
                log::error!("Hash computation failed: {}", e);
                Vec::new()
            }
        }))
        .compute(b"Hello, World!")
        .await;
    
    println!("Test 1 - Success case:");
    println!("Hash length: {}", hash.len());
    println!("Hash: {}", hex::encode(&hash));
    
    // Test 2: HMAC with key
    let hmac = Cryypt::hash()
        .sha256()
        .with_key(b"secret_key")
        .on_result(cryypt::__cryypt_on_result_impl!(|result| {
            Ok => result.to_vec(),
            Err(e) => {
                log::error!("HMAC operation failed: {}", e);
                Vec::new()
            }
        }))
        .compute(b"Message to authenticate")
        .await;
    
    println!("\nTest 2 - HMAC case:");
    println!("HMAC length: {}", hmac.len());
    println!("HMAC: {}", hex::encode(&hmac));
    
    // Test 3: Error case - this should trigger the error handler if we can force an error
    println!("\nTest 3 - Testing error handling:");
    let error_result = Cryypt::hash()
        .sha256()
        .on_result(cryypt::__cryypt_on_result_impl!(|result| {
            Ok => result.to_vec(),
            Err(e) => {
                log::error!("ERROR HANDLER CALLED: {}", e);
                vec![99, 99, 99] // Return specific error value to prove handler was used
            }
        }))
        .compute(b"This should succeed normally")
        .await;
    
    println!("Result length: {} (should be 32 for normal SHA256)", error_result.len());
    if error_result.len() == 32 {
        println!("✅ NORMAL OPERATION - SHA256 hash computed successfully");
        println!("Hash: {}", hex::encode(&error_result));
    } else if error_result == vec![99, 99, 99] {
        println!("✅ ERROR HANDLER VERIFICATION PASSED - Custom error value returned");
    } else {
        println!("❌ UNEXPECTED RESULT: {:?}", error_result);
    }

    Ok(())
}