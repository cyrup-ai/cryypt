//! Comprehensive compression tests for all algorithms with 100% coverage

use cryypt_compression::{Compress, CompressionError, DataBuilder, CompressExecutor, DecompressExecutor, LevelBuilder};

#[tokio::test]
async fn test_zstd_basic_compression_decompression() {
    let original_data = b"Hello, Zstd compression! This is a test string that should compress well.";
    
    let compressed = Compress::zstd()
        .with_data(original_data)
        .compress()
        .await
        .expect("Zstd compression should succeed");
    
    assert!(!compressed.is_empty());
    assert_ne!(compressed, original_data);
    
    let decompressed = Compress::zstd()
        .with_data(compressed)
        .decompress()
        .await
        .expect("Zstd decompression should succeed");
    
    assert_eq!(decompressed, original_data);
}

#[tokio::test]
async fn test_zstd_with_text() {
    let original_text = "Hello, Zstd! 🦀 This text contains unicode characters: 中文 émojis 🌍";
    
    let compressed = Compress::zstd()
        .with_text(original_text)
        .compress()
        .await
        .expect("Zstd text compression should succeed");
    
    let decompressed = Compress::zstd()
        .with_data(compressed)
        .decompress()
        .await
        .expect("Zstd text decompression should succeed");
    
    assert_eq!(decompressed, original_text.as_bytes());
}

#[tokio::test]
async fn test_zstd_with_level() {
    let original_data = b"Test data for level-specific compression testing. ".repeat(10);
    
    let compressed = Compress::zstd()
        .with_data(original_data.clone())
        .with_level(10)
        .compress()
        .await
        .expect("Zstd level compression should succeed");
    
    let decompressed = Compress::zstd()
        .with_data(compressed)
        .decompress()
        .await
        .expect("Zstd level decompression should succeed");
    
    assert_eq!(decompressed, original_data);
}

#[tokio::test]
async fn test_zstd_max_compression() {
    let original_data = b"Maximum compression test data. ".repeat(20);
    
    let compressed = Compress::zstd()
        .with_data(original_data.clone())
        .max_compression()
        .compress()
        .await
        .expect("Zstd max compression should succeed");
    
    let decompressed = Compress::zstd()
        .with_data(compressed)
        .decompress()
        .await
        .expect("Zstd max decompression should succeed");
    
    assert_eq!(decompressed, original_data);
}

#[tokio::test]
async fn test_zstd_level_clamping() {
    let original_data = b"Level clamping test data";
    
    // Test with level above maximum (should be clamped to 22)
    let compressed = Compress::zstd()
        .with_data(original_data)
        .with_level(50)
        .compress()
        .await
        .expect("Zstd high level compression should succeed");
    
    let decompressed = Compress::zstd()
        .with_data(compressed)
        .decompress()
        .await
        .expect("Zstd high level decompression should succeed");
    
    assert_eq!(decompressed, original_data);
}

#[tokio::test]
async fn test_gzip_basic_compression_decompression() {
    let original_data = b"Hello, Gzip compression! This should compress efficiently.";
    
    let compressed = Compress::gzip()
        .with_data(original_data)
        .compress()
        .await
        .expect("Gzip compression should succeed");
    
    assert!(!compressed.is_empty());
    assert_ne!(compressed, original_data);
    
    let decompressed = Compress::gzip()
        .with_data(compressed)
        .decompress()
        .await
        .expect("Gzip decompression should succeed");
    
    assert_eq!(decompressed, original_data);
}

#[tokio::test]
async fn test_gzip_with_text() {
    let original_text = "Gzip text compression test with unicode: 🗜️ 压缩 compression!";
    
    let compressed = Compress::gzip()
        .with_text(original_text)
        .compress()
        .await
        .expect("Gzip text compression should succeed");
    
    let decompressed = Compress::gzip()
        .with_data(compressed)
        .decompress()
        .await
        .expect("Gzip text decompression should succeed");
    
    assert_eq!(decompressed, original_text.as_bytes());
}

#[tokio::test]
async fn test_gzip_with_level() {
    let original_data = b"Gzip level compression test data. ".repeat(15);
    
    let compressed = Compress::gzip()
        .with_data(original_data.clone())
        .with_level(9)
        .compress()
        .await
        .expect("Gzip level compression should succeed");
    
    let decompressed = Compress::gzip()
        .with_data(compressed)
        .decompress()
        .await
        .expect("Gzip level decompression should succeed");
    
    assert_eq!(decompressed, original_data);
}

#[tokio::test]
async fn test_bzip2_basic_compression_decompression() {
    let original_data = b"Hello, Bzip2 compression! This data should compress with bzip2 algorithm.";
    
    let compressed = Compress::bzip2()
        .with_data(original_data)
        .compress()
        .await
        .expect("Bzip2 compression should succeed");
    
    assert!(!compressed.is_empty());
    assert_ne!(compressed, original_data);
    
    let decompressed = Compress::bzip2()
        .with_data(compressed)
        .decompress()
        .await
        .expect("Bzip2 decompression should succeed");
    
    assert_eq!(decompressed, original_data);
}

#[tokio::test]
async fn test_bzip2_max_compression() {
    let original_data = b"Bzip2 maximum compression test. ".repeat(25);
    
    let compressed = Compress::bzip2()
        .with_data(original_data.clone())
        .max_compression()
        .compress()
        .await
        .expect("Bzip2 max compression should succeed");
    
    let decompressed = Compress::bzip2()
        .with_data(compressed)
        .decompress()
        .await
        .expect("Bzip2 max decompression should succeed");
    
    assert_eq!(decompressed, original_data);
}

#[tokio::test]
async fn test_bzip2_balanced_compression() {
    let original_data = b"Bzip2 balanced compression test. ".repeat(20);
    
    let compressed = Compress::bzip2()
        .with_data(original_data.clone())
        .balanced_compression()
        .compress()
        .await
        .expect("Bzip2 balanced compression should succeed");
    
    let decompressed = Compress::bzip2()
        .with_data(compressed)
        .decompress()
        .await
        .expect("Bzip2 balanced decompression should succeed");
    
    assert_eq!(decompressed, original_data);
}

#[tokio::test]
async fn test_zip_basic_compression_decompression() {
    let original_data = b"Hello, Zip compression! This should work with zip algorithm.";
    
    let compressed = Compress::zip()
        .with_data(original_data)
        .compress()
        .await
        .expect("Zip compression should succeed");
    
    assert!(!compressed.is_empty());
    assert_ne!(compressed, original_data);
    
    let decompressed = Compress::zip()
        .with_data(compressed)
        .decompress()
        .await
        .expect("Zip decompression should succeed");
    
    assert_eq!(decompressed, original_data);
}

#[tokio::test]
async fn test_zip_with_level() {
    let original_data = b"Zip level compression test data. ".repeat(12);
    
    let compressed = Compress::zip()
        .with_data(original_data.clone())
        .with_level(6)
        .compress()
        .await
        .expect("Zip level compression should succeed");
    
    let decompressed = Compress::zip()
        .with_data(compressed)
        .decompress()
        .await
        .expect("Zip level decompression should succeed");
    
    assert_eq!(decompressed, original_data);
}

#[tokio::test]
async fn test_empty_data_compression() {
    let empty_data = b"";
    
    // Test all algorithms with empty data
    let algorithms = ["zstd", "gzip", "bzip2", "zip"];
    
    for name in algorithms {
        let compressed = match name {
            "zstd" => Compress::zstd().with_data(empty_data).compress().await,
            "gzip" => Compress::gzip().with_data(empty_data).compress().await,
            "bzip2" => Compress::bzip2().with_data(empty_data).compress().await,
            "zip" => Compress::zip().with_data(empty_data).compress().await,
            _ => unreachable!(),
        }.expect(&format!("{} empty compression should succeed", name));
        
        // Even empty data should produce some output (headers, etc.)
        assert!(!compressed.is_empty(), "{} should produce non-empty output", name);
        
        let decompressed = match name {
            "zstd" => Compress::zstd().with_data(compressed).decompress().await,
            "gzip" => Compress::gzip().with_data(compressed).decompress().await,
            "bzip2" => Compress::bzip2().with_data(compressed).decompress().await,
            "zip" => Compress::zip().with_data(compressed).decompress().await,
            _ => unreachable!(),
        }.expect(&format!("{} empty decompression should succeed", name));
        
        assert_eq!(decompressed, empty_data, "{} failed with empty data", name);
    }
}

#[tokio::test]
async fn test_large_data_compression() {
    let large_data = vec![0x55u8; 100_000]; // 100KB of repeated data
    
    let algorithms = ["zstd", "gzip", "bzip2", "zip"];
    
    for name in algorithms {
        let compressed = match name {
            "zstd" => Compress::zstd().with_data(large_data.clone()).compress().await,
            "gzip" => Compress::gzip().with_data(large_data.clone()).compress().await,
            "bzip2" => Compress::bzip2().with_data(large_data.clone()).compress().await,
            "zip" => Compress::zip().with_data(large_data.clone()).compress().await,
            _ => unreachable!(),
        }.expect(&format!("{} large data compression should succeed", name));
        
        // Compressed data should be much smaller than original
        assert!(compressed.len() < large_data.len() / 10, 
                "{} should compress repeated data significantly", name);
        
        let decompressed = match name {
            "zstd" => Compress::zstd().with_data(compressed).decompress().await,
            "gzip" => Compress::gzip().with_data(compressed).decompress().await,
            "bzip2" => Compress::bzip2().with_data(compressed).decompress().await,
            "zip" => Compress::zip().with_data(compressed).decompress().await,
            _ => unreachable!(),
        }.expect(&format!("{} large data decompression should succeed", name));
        
        assert_eq!(decompressed, large_data, "{} failed with large data", name);
    }
}

#[tokio::test]
async fn test_random_data_compression() {
    // Random data should not compress well
    let mut random_data = vec![0u8; 1000];
    for (i, byte) in random_data.iter_mut().enumerate() {
        *byte = (i * 17 + 42) as u8; // Pseudo-random pattern
    }
    
    let compressed = Compress::zstd()
        .with_data(random_data.clone())
        .compress()
        .await
        .expect("Random data compression should succeed");
    
    // Random data typically doesn't compress much
    assert!(compressed.len() >= random_data.len() * 90 / 100, 
            "Random data should not compress significantly");
    
    let decompressed = Compress::zstd()
        .with_data(compressed)
        .decompress()
        .await
        .expect("Random data decompression should succeed");
    
    assert_eq!(decompressed, random_data);
}

#[tokio::test]
async fn test_compression_levels_comparison() {
    let test_data = b"This is test data for compression level comparison. ".repeat(50);
    
    // Test different compression levels for zstd
    let mut compressed_sizes = Vec::new();
    for level in [1, 5, 10, 15, 22] {
        let compressed = Compress::zstd()
            .with_data(test_data.clone())
            .with_level(level)
            .compress()
            .await
            .expect(&format!("Zstd level {} compression should succeed", level));
        
        compressed_sizes.push((level, compressed.len()));
        
        // Verify decompression works
        let decompressed = Compress::zstd()
            .with_data(compressed)
            .decompress()
            .await
            .expect(&format!("Zstd level {} decompression should succeed", level));
        
        assert_eq!(decompressed, test_data);
    }
    
    // Higher compression levels should generally produce smaller output
    println!("Zstd compression sizes by level: {:?}", compressed_sizes);
    assert!(compressed_sizes[0].1 >= compressed_sizes[4].1, 
            "Higher compression levels should produce smaller output");
}

// Error condition tests
#[tokio::test]
async fn test_invalid_compressed_data() {
    let invalid_data = b"This is not valid compressed data";
    
    let algorithms = ["zstd", "gzip", "bzip2", "zip"];
    
    for name in algorithms {
        let result = match name {
            "zstd" => Compress::zstd().with_data(invalid_data).decompress().await,
            "gzip" => Compress::gzip().with_data(invalid_data).decompress().await,
            "bzip2" => Compress::bzip2().with_data(invalid_data).decompress().await,
            "zip" => Compress::zip().with_data(invalid_data).decompress().await,
            _ => unreachable!(),
        };
        
        assert!(result.is_err(), "{} should fail with invalid data", name);
        
        let error = result.unwrap_err();
        assert!(matches!(error, CompressionError::DecompressionFailed(_)), 
                "{} should return decompression error", name);
    }
}

#[tokio::test]
async fn test_corrupted_compressed_data() {
    let original_data = b"Test data for corruption testing";
    
    // Compress with each algorithm
    let algorithms = ["zstd", "gzip", "bzip2", "zip"];
    
    for name in algorithms {
        let mut compressed = match name {
            "zstd" => Compress::zstd().with_data(original_data).compress().await,
            "gzip" => Compress::gzip().with_data(original_data).compress().await,
            "bzip2" => Compress::bzip2().with_data(original_data).compress().await,
            "zip" => Compress::zip().with_data(original_data).compress().await,
            _ => unreachable!(),
        }.expect(&format!("{} compression should succeed", name));
        
        // Corrupt the compressed data
        if compressed.len() > 10 {
            compressed[5] = compressed[5].wrapping_add(1);
            let len = compressed.len();
            compressed[len - 5] = compressed[len - 5].wrapping_add(1);
        }
        
        let result = match name {
            "zstd" => Compress::zstd().with_data(compressed).decompress().await,
            "gzip" => Compress::gzip().with_data(compressed).decompress().await,
            "bzip2" => Compress::bzip2().with_data(compressed).decompress().await,
            "zip" => Compress::zip().with_data(compressed).decompress().await,
            _ => unreachable!(),
        };
        
        assert!(result.is_err(), "{} should fail with corrupted data", name);
    }
}

#[tokio::test]
async fn test_all_byte_values() {
    // Test with data containing all possible byte values
    let all_bytes: Vec<u8> = (0..=255).collect();
    
    let algorithms = ["zstd", "gzip", "bzip2", "zip"];
    
    for name in algorithms {
        let compressed = match name {
            "zstd" => Compress::zstd().with_data(all_bytes.clone()).compress().await,
            "gzip" => Compress::gzip().with_data(all_bytes.clone()).compress().await,
            "bzip2" => Compress::bzip2().with_data(all_bytes.clone()).compress().await,
            "zip" => Compress::zip().with_data(all_bytes.clone()).compress().await,
            _ => unreachable!(),
        }.expect(&format!("{} all bytes compression should succeed", name));
        
        let decompressed = match name {
            "zstd" => Compress::zstd().with_data(compressed).decompress().await,
            "gzip" => Compress::gzip().with_data(compressed).decompress().await,
            "bzip2" => Compress::bzip2().with_data(compressed).decompress().await,
            "zip" => Compress::zip().with_data(compressed).decompress().await,
            _ => unreachable!(),
        }.expect(&format!("{} all bytes decompression should succeed", name));
        
        assert_eq!(decompressed, all_bytes, "{} failed with all byte values", name);
    }
}

#[tokio::test]
async fn test_unicode_text_all_algorithms() {
    let unicode_text = "Hello 世界! 🦀 Rust compression with émojis 🌍 and various scripts: Русский العربية ελληνικά";
    
    let algorithms = ["zstd", "gzip", "bzip2", "zip"];
    
    for name in algorithms {
        let compressed = match name {
            "zstd" => Compress::zstd().with_text(unicode_text).compress().await,
            "gzip" => Compress::gzip().with_text(unicode_text).compress().await,
            "bzip2" => Compress::bzip2().with_text(unicode_text).compress().await,
            "zip" => Compress::zip().with_text(unicode_text).compress().await,
            _ => unreachable!(),
        }.expect(&format!("{} unicode compression should succeed", name));
        
        let decompressed = match name {
            "zstd" => Compress::zstd().with_data(compressed).decompress().await,
            "gzip" => Compress::gzip().with_data(compressed).decompress().await,
            "bzip2" => Compress::bzip2().with_data(compressed).decompress().await,
            "zip" => Compress::zip().with_data(compressed).decompress().await,
            _ => unreachable!(),
        }.expect(&format!("{} unicode decompression should succeed", name));
        
        assert_eq!(decompressed, unicode_text.as_bytes(), "{} failed with unicode", name);
    }
}

#[tokio::test]
async fn test_compression_efficiency() {
    // Test that compression actually reduces size for redundant data
    let redundant_data = b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".repeat(100);
    
    let algorithms = ["zstd", "gzip", "bzip2", "zip"];
    
    for name in algorithms {
        let compressed = match name {
            "zstd" => Compress::zstd().with_data(redundant_data.clone()).compress().await,
            "gzip" => Compress::gzip().with_data(redundant_data.clone()).compress().await,
            "bzip2" => Compress::bzip2().with_data(redundant_data.clone()).compress().await,
            "zip" => Compress::zip().with_data(redundant_data.clone()).compress().await,
            _ => unreachable!(),
        }.expect(&format!("{} redundant compression should succeed", name));
        
        // Should achieve significant compression on redundant data
        assert!(compressed.len() < redundant_data.len() / 20, 
                "{} should compress redundant data to <5% of original size", name);
        
        let decompressed = match name {
            "zstd" => Compress::zstd().with_data(compressed).decompress().await,
            "gzip" => Compress::gzip().with_data(compressed).decompress().await,
            "bzip2" => Compress::bzip2().with_data(compressed).decompress().await,
            "zip" => Compress::zip().with_data(compressed).decompress().await,
            _ => unreachable!(),
        }.expect(&format!("{} redundant decompression should succeed", name));
        
        assert_eq!(decompressed, redundant_data, "{} failed with redundant data", name);
    }
}

#[tokio::test]
async fn test_concurrent_compression() {
    let test_data = b"Concurrent compression test data. ".repeat(50);
    
    // Spawn multiple concurrent compression tasks
    let mut handles = vec![];
    for i in 0..10 {
        let data = format!("{} - iteration {}", 
                          std::str::from_utf8(&test_data).unwrap(), i);
        
        let handle = tokio::spawn(async move {
            let compressed = Compress::zstd()
                .with_text(&data)
                .compress()
                .await?;
            
            let decompressed = Compress::zstd()
                .with_data(compressed)
                .decompress()
                .await?;
            
            Ok::<_, CompressionError>((data, decompressed))
        });
        handles.push(handle);
    }
    
    // Verify all tasks completed successfully
    for handle in handles {
        let (original, decompressed) = handle.await
            .expect("Task should complete")
            .expect("Compression/decompression should succeed");
        
        assert_eq!(decompressed, original.as_bytes());
    }
}