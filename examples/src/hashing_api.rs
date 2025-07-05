//! Hashing API examples - EXACTLY matching hashing/README.md

use cryypt::{Cryypt, on_result, Hash};

/// Basic Hashing example from README
async fn basic_hashing_example() -> Result<(), Box<dyn std::error::Error>> {
    // SHA-256 hash
    let hash = Cryypt::hash()
        .sha256()
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("Hash error: {}", e))
        })
        .compute(b"Hello, World!")
        .await; // Returns fully unwrapped value - no Result wrapper

    println!("SHA-256: {}", hex::encode(&hash));

    // SHA3-256 hash
    let hash = Cryypt::hash()
        .sha3_256()
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("Hash error: {}", e))
        })
        .compute(b"Hello, World!")
        .await; // Returns fully unwrapped value - no Result wrapper

    println!("SHA3-256: {}", hex::encode(&hash));

    // BLAKE2b hash with custom output size
    let hash = Cryypt::hash()
        .blake2b_512()
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("Hash error: {}", e))
        })
        .compute(b"Hello, World!")
        .await; // Returns fully unwrapped value - no Result wrapper

    println!("BLAKE2b-512: {}", hex::encode(&hash));

    Ok(())
}

/// Streaming Hash example from README
async fn streaming_hash_example() -> Result<(), Box<dyn std::error::Error>> {
    // Stream hashing for large files
    let file_stream = tokio::fs::File::open("/etc/hosts").await?;
    
    let hash = Cryypt::hash()
        .sha256()
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("Hash error: {}", e))
        })
        .compute_stream(file_stream)
        .await; // Returns fully unwrapped value - no Result wrapper

    println!("File SHA-256: {}", hex::encode(&hash));

    // Alternative: Direct builders are also available
    let hash = Hash::sha256()
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("Hash error: {}", e))
        })
        .compute(b"Hello, World!")
        .await; // Returns fully unwrapped value - no Result wrapper

    println!("Direct builder SHA-256: {}", hex::encode(&hash));

    Ok(())
}

/// Multi-pass Hashing example from README
async fn multi_pass_hashing_example() -> Result<(), Box<dyn std::error::Error>> {
    // Create hasher for multiple inputs
    let mut hasher = Cryypt::hash()
        .sha256()
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("Hash error: {}", e))
        })
        .multi_pass();

    // Add multiple pieces of data
    hasher.update(b"Part 1");
    hasher.update(b"Part 2");
    hasher.update(b"Part 3");

    // Get final hash
    let hash = hasher.finalize().await; // Returns fully unwrapped value - no Result wrapper

    println!("Multi-pass hash: {}", hex::encode(&hash));

    Ok(())
}

/// File Integrity Verification example from README
async fn file_integrity_example() -> Result<(), Box<dyn std::error::Error>> {
    use cryypt::{Hash, on_result};
    use tokio::fs::File;
    
    // Calculate file hash
    async fn hash_file(path: &str) -> Vec<u8> {
        let file = File::open(path).await.unwrap();
        
        Hash::sha256()
            .on_result!(|result| {
                result.unwrap_or_else(|e| panic!("Hash error: {}", e))
            })
            .compute_stream(file)
            .await // Returns fully unwrapped value - no Result wrapper
    }
    
    // Verify file integrity
    async fn verify_file(path: &str, expected_hash: &[u8]) -> bool {
        let actual_hash = hash_file(path).await;
        actual_hash == expected_hash
    }
    
    // Example usage
    let test_file = "/tmp/test_hash.txt";
    tokio::fs::write(test_file, b"Test content").await?;
    
    let original_hash = hash_file(test_file).await;
    println!("Original hash: {}", hex::encode(&original_hash));
    
    let is_valid = verify_file(test_file, &original_hash).await;
    println!("File integrity check: {}", if is_valid { "PASS" } else { "FAIL" });
    
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Basic Hashing ===");
    basic_hashing_example().await?;
    
    println!("\n=== Streaming Hash ===");
    streaming_hash_example().await?;
    
    println!("\n=== Multi-pass Hashing ===");
    multi_pass_hashing_example().await?;
    
    println!("\n=== File Integrity Verification ===");
    file_integrity_example().await?;
    
    Ok(())
}