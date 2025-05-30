// Standalone test to verify nonce implementation
use cryypt::cipher::{NonceConfig, NonceManager, NonceSecretKey};
use std::time::Duration;

#[tokio::main]
async fn main() {
    println!("Testing nonce generation and verification...");
    
    // Test 1: Basic generation and verification
    let key = NonceSecretKey::generate();
    let mgr = NonceManager::new(&key, None);
    
    let nonce = mgr.generate_os().await;
    println!("Generated nonce: {} (length: {})", nonce.as_str(), nonce.as_str().len());
    
    match mgr.verify(nonce.as_str()) {
        Ok(parsed) => {
            println!("✓ Verification successful");
            println!("  Timestamp: {}", parsed.timestamp_ns);
            println!("  Random bytes: {}", parsed.random.len());
        }
        Err(e) => {
            println!("✗ Verification failed: {}", e);
        }
    }
    
    // Test 2: Replay detection
    println!("\nTesting replay detection...");
    match mgr.verify(nonce.as_str()) {
        Ok(_) => println!("✗ Replay detection failed - second verification should fail"),
        Err(e) => {
            if e.to_string().contains("replay detected") {
                println!("✓ Replay detection working correctly");
            } else {
                println!("✗ Wrong error: {}", e);
            }
        }
    }
    
    // Test 3: Expiration
    println!("\nTesting expiration...");
    let config = NonceConfig {
        ttl: Duration::from_millis(10),
    };
    let mgr2 = NonceManager::new(&key, Some(config));
    let nonce2 = mgr2.generate_os().await;
    
    tokio::time::sleep(Duration::from_millis(20)).await;
    
    match mgr2.verify(nonce2.as_str()) {
        Ok(_) => println!("✗ Expiration check failed - old nonce should be expired"),
        Err(e) => {
            if e.to_string().contains("expired") {
                println!("✓ Expiration working correctly");
            } else {
                println!("✗ Wrong error: {}", e);
            }
        }
    }
    
    println!("\nAll nonce tests completed!");
}