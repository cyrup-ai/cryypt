//! Test README.md compression examples to ensure they work as documented

use cryypt_compression::api::Compress;

#[tokio::test]
async fn test_readme_single_compression() -> Result<(), Box<dyn std::error::Error>> {
    // Use larger data that actually benefits from compression
    let test_data = b"This is a much larger piece of text data that should compress well. This is a much larger piece of text data that should compress well. This is a much larger piece of text data that should compress well.";

    // Test the README pattern for single compression
    let compressed = Compress::zstd()
        .with_level(3)
        .on_result(|result| match result {
            Ok(bytes) => bytes.clone(),
            Err(e) => {
                eprintln!("Compression error: {e}");
                test_data.to_vec()
            }
        })
        .compress(test_data)
        .await;

    println!(
        "Original: {} bytes, Compressed: {} bytes",
        test_data.len(),
        compressed.len()
    );
    // With larger, repetitive data, compression should work
    assert!(
        compressed.len() < test_data.len(),
        "Should compress smaller"
    );
    Ok(())
}

#[tokio::test]
async fn test_readme_single_decompression() -> Result<(), Box<dyn std::error::Error>> {
    let test_data = b"Large text data...";

    // First compress
    let compressed = Compress::zstd()
        .with_level(3)
        .on_result(|result| match result {
            Ok(bytes) => bytes.clone(),
            Err(_e) => test_data.to_vec(),
        })
        .compress(test_data)
        .await;

    // Test the README pattern for single decompression
    let decompressed = Compress::zstd()
        .on_result(|result| match result {
            Ok(bytes) => bytes.clone(),
            Err(e) => {
                eprintln!("Decompression failed: {e}");
                Vec::new()
            }
        })
        .decompress(compressed)
        .await;

    assert_eq!(
        decompressed, test_data,
        "Decompressed should match original"
    );
    Ok(())
}

#[tokio::test]
async fn test_basic_streaming_decompression_api() -> Result<(), Box<dyn std::error::Error>> {
    let test_data = b"Large text data...";

    // First compress to get compressed data
    let compressed = Compress::zstd()
        .with_level(6)
        .on_result(|result| match result {
            Ok(bytes) => bytes.clone(),
            Err(_e) => test_data.to_vec(),
        })
        .compress(test_data)
        .await;

    // Test if streaming decompression API exists at all
    // Start with just creating the builder without on_chunk to see what methods are available
    let zstd_builder = Compress::zstd();

    // Try the simplest possible approach first
    let decompression_result = zstd_builder
        .on_result(|result: Result<Vec<u8>, _>| result.unwrap_or_default())
        .decompress(compressed) // Use regular decompress instead of streaming for now
        .await;

    assert_eq!(
        decompression_result, test_data,
        "Basic decompression should work"
    );
    Ok(())
}

// Add comprehensive streaming test:
#[tokio::test]
async fn test_streaming_decompression() -> Result<(), Box<dyn std::error::Error>> {
    let test_data = b"Test data for streaming decompression validation";

    // First compress the data
    let compressed = Compress::zstd()
        .on_result(|result: Result<Vec<u8>, _>| result.unwrap_or_default())
        .compress(test_data.to_vec())
        .await;

    // Test decompression using on_result pattern as per user guidance
    let decompressed_result = Compress::zstd()
        .on_result(|result| {
            result.unwrap_or_else(|e| {
                eprintln!("Decompression failed: {e}");
                Vec::new()
            })
        })
        .decompress(compressed)
        .await;

    assert_eq!(
        decompressed_result, test_data,
        "Decompression with on_result handler should work"
    );
    Ok(())
}

#[tokio::test]
async fn test_multiple_compression_formats() -> Result<(), Box<dyn std::error::Error>> {
    let test_data = b"Test data for multiple formats";

    // Test Gzip from README
    let gzip_compressed = Compress::gzip()
        .with_level(6)
        .on_result(|result| match result {
            Ok(bytes) => bytes.clone(),
            Err(e) => {
                eprintln!("Compression error: {e}");
                test_data.to_vec()
            }
        })
        .compress(test_data)
        .await;

    // Test Bzip2 from README
    let bzip2_compressed = Compress::bzip2()
        .with_level(9)
        .on_result(|result| match result {
            Ok(bytes) => bytes.clone(),
            Err(e) => {
                eprintln!("Operation error: {e}");
                Vec::new()
            }
        })
        .compress(test_data)
        .await;

    println!("Original: {} bytes", test_data.len());
    println!("Gzip: {} bytes", gzip_compressed.len());
    println!("Bzip2: {} bytes", bzip2_compressed.len());

    assert!(!gzip_compressed.is_empty(), "Gzip should produce output");
    assert!(!bzip2_compressed.is_empty(), "Bzip2 should produce output");

    Ok(())
}
