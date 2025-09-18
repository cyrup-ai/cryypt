//! Test the fluent compression API exactly as documented in README.md

use cryypt_compression::Compress;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Testing Cryypt fluent compression API...");

    let test_data = b"Large text data to compress for testing the fluent API";

    // Test basic compression - Direct Compress API (equivalent to Cryypt::compress())
    let compressed = Compress::zstd()
        .with_level(3)
        .on_result(|result| match result {
            Ok(bytes) => {
                println!("Compression successful: {} bytes", bytes.len());
                bytes
            }
            Err(e) => {
                eprintln!("Compression failed: {}", e);
                panic!("Critical compression failure")
            }
        })
        .compress(test_data)
        .await;

    println!(
        "Compressed {} bytes to {} bytes",
        test_data.len(),
        compressed.len()
    );

    // Test decompression
    let compressed_clone = compressed.clone();
    let decompressed = Compress::zstd()
        .with_level(3)
        .on_result(|result| match result {
            Ok(bytes) => {
                println!("Decompression successful: {} bytes", bytes.len());
                bytes
            }
            Err(e) => {
                eprintln!("Decompression failed: {}", e);
                panic!("Critical decompression failure")
            }
        })
        .decompress(compressed_clone)
        .await;

    println!(
        "Decompressed {} bytes back to {} bytes",
        compressed.len(),
        decompressed.len()
    );

    // Verify round-trip
    if decompressed == test_data {
        println!("✅ Round-trip successful - data matches original");
    } else {
        println!("❌ Round-trip failed - data does not match");
        return Err("Round-trip verification failed".into());
    }

    Ok(())
}
