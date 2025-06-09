//! Example demonstrating the HashPasses enum for production-safe hash iterations

use cryypt::hashing::api::HashPasses;
use cryypt::prelude::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let test_data = b"Example data for hashing";
    let salt = b"production_salt";

    println!("=== HashPasses Enum Demo ===\n");

    // Fast hashing (100 iterations) - Development only
    println!(
        "Fast hashing ({}): {}",
        HashPasses::Fast.security_level(),
        HashPasses::Fast.iterations()
    );
    let fast_hash = Hash::sha256()
        .with_data(test_data)
        .with_salt(salt)
        .with_passes(HashPasses::Fast)
        .hash()
        .await?;
    println!("Hash length: {} bytes\n", fast_hash.len());

    // Default hashing (10,000 iterations) - Production ready
    println!(
        "Default hashing ({}): {} iterations",
        HashPasses::Default.security_level(),
        HashPasses::Default.iterations()
    );
    let default_hash = Hash::sha256()
        .with_data(test_data)
        .with_salt(salt)
        .with_passes(HashPasses::Default)
        .hash()
        .await?;
    println!("Hash length: {} bytes", default_hash.len());
    println!(
        "Is password safe: {}\n",
        HashPasses::Default.is_password_safe()
    );

    // Strong hashing (100,000 iterations) - High security
    println!(
        "Strong hashing ({}): {} iterations",
        HashPasses::Strong.security_level(),
        HashPasses::Strong.iterations()
    );
    let strong_hash = Hash::sha256()
        .with_data(test_data)
        .with_salt(salt)
        .with_passes(HashPasses::Strong)
        .hash()
        .await?;
    println!("Hash length: {} bytes\n", strong_hash.len());

    // Verify different pass counts produce different hashes
    assert_ne!(fast_hash, default_hash);
    assert_ne!(default_hash, strong_hash);
    assert_ne!(fast_hash, strong_hash);

    println!("✅ All hashes are different (as expected)");
    println!("✅ Zero passes are impossible at compile time!");

    // The following would not compile:
    // .with_passes(0)  // Error: expected HashPasses, found integer

    Ok(())
}
