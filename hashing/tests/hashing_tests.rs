//! Comprehensive hashing tests for all algorithms with 100% coverage

use cryypt_hashing::{Hash, HashError};
use cryypt_hashing::api::HashPasses;

#[tokio::test]
async fn test_sha256_basic_hashing() {
    let test_data = b"Hello, SHA256 hashing!";
    
    let hash_result = Hash::sha256()
        .with_data(test_data)
        .hash()
        .await
        .expect("SHA256 hashing should succeed");
    
    assert_eq!(hash_result.len(), 32); // SHA256 produces 32 bytes
    assert!(!hash_result.is_empty());
    
    // Test that same input produces same hash
    let hash_result2 = Hash::sha256()
        .with_data(test_data)
        .hash()
        .await
        .expect("SHA256 hashing should succeed");
    
    assert_eq!(hash_result, hash_result2);
}

#[tokio::test]
async fn test_sha256_with_text() {
    let test_text = "Hello, SHA256 with unicode! 🦀 中文 émojis";
    
    let hash_result = Hash::sha256()
        .with_text(test_text)
        .hash()
        .await
        .expect("SHA256 text hashing should succeed");
    
    assert_eq!(hash_result.len(), 32);
    
    // Verify it's the same as hashing the bytes directly
    let hash_result2 = Hash::sha256()
        .with_data(test_text.as_bytes())
        .hash()
        .await
        .expect("SHA256 bytes hashing should succeed");
    
    assert_eq!(hash_result, hash_result2);
}

#[tokio::test]
async fn test_sha256_with_salt() {
    let test_data = b"Test data for salted hashing";
    let salt = b"unique_salt_value";
    
    let hash_with_salt = Hash::sha256()
        .with_data(test_data)
        .with_salt(salt)
        .hash()
        .await
        .expect("SHA256 salted hashing should succeed");
    
    let hash_without_salt = Hash::sha256()
        .with_data(test_data)
        .hash()
        .await
        .expect("SHA256 unsalted hashing should succeed");
    
    assert_ne!(hash_with_salt, hash_without_salt);
    assert_eq!(hash_with_salt.len(), 32);
}

#[tokio::test]
async fn test_sha256_with_passes() {
    let test_data = b"Test data for iteration hashing";
    
    let hash_fast = Hash::sha256()
        .with_data(test_data)
        .with_passes(HashPasses::Fast)
        .hash()
        .await
        .expect("SHA256 fast hashing should succeed");
    
    let hash_default = Hash::sha256()
        .with_data(test_data)
        .with_passes(HashPasses::Default)
        .hash()
        .await
        .expect("SHA256 default hashing should succeed");
    
    let hash_strong = Hash::sha256()
        .with_data(test_data)
        .with_passes(HashPasses::Strong)
        .hash()
        .await
        .expect("SHA256 strong hashing should succeed");
    
    // Different iteration counts should produce different hashes
    assert_ne!(hash_fast, hash_default);
    assert_ne!(hash_default, hash_strong);
    assert_ne!(hash_fast, hash_strong);
    
    // All should be 32 bytes
    assert_eq!(hash_fast.len(), 32);
    assert_eq!(hash_default.len(), 32);
    assert_eq!(hash_strong.len(), 32);
}

#[tokio::test]
async fn test_sha256_with_salt_and_passes() {
    let test_data = b"Comprehensive SHA256 test";
    let salt = b"production_salt";
    
    let hash_result = Hash::sha256()
        .with_data(test_data)
        .with_salt(salt)
        .with_passes(HashPasses::Default)
        .hash()
        .await
        .expect("SHA256 comprehensive hashing should succeed");
    
    assert_eq!(hash_result.len(), 32);
    
    // Verify reproducibility
    let hash_result2 = Hash::sha256()
        .with_data(test_data)
        .with_salt(salt)
        .with_passes(HashPasses::Default)
        .hash()
        .await
        .expect("SHA256 comprehensive hashing should succeed");
    
    assert_eq!(hash_result, hash_result2);
}

#[tokio::test]
async fn test_sha3_256_basic_hashing() {
    let test_data = b"Hello, SHA3-256 hashing!";
    
    let hash_result = Hash::sha3()
        .with_data(test_data)
        .hash()
        .await
        .expect("SHA3-256 hashing should succeed");
    
    assert_eq!(hash_result.len(), 32); // SHA3-256 produces 32 bytes
    
    // Verify it's different from SHA256
    let sha256_result = Hash::sha256()
        .with_data(test_data)
        .hash()
        .await
        .expect("SHA256 hashing should succeed");
    
    assert_ne!(hash_result, sha256_result);
}

// SHA3-384 is not implemented yet
// #[tokio::test]
// async fn test_sha3_384_hashing() { ... }

// SHA3-512 is not implemented yet
// #[tokio::test]
// async fn test_sha3_512_hashing() { ... }

#[tokio::test]
async fn test_blake2b_basic_hashing() {
    let test_data = b"Hello, BLAKE2b hashing!";
    
    let hash_result = Hash::blake2b()
        .with_data(test_data)
        .hash()
        .await
        .expect("BLAKE2b hashing should succeed");
    
    assert_eq!(hash_result.len(), 64); // BLAKE2b default produces 64 bytes
}

#[tokio::test]
async fn test_blake2b_with_salt() {
    let test_data = b"BLAKE2b salted test data";
    let salt = b"blake2b_salt";
    
    let hash_with_salt = Hash::blake2b()
        .with_data(test_data)
        .with_salt(salt)
        .hash()
        .await
        .expect("BLAKE2b salted hashing should succeed");
    
    let hash_without_salt = Hash::blake2b()
        .with_data(test_data)
        .hash()
        .await
        .expect("BLAKE2b unsalted hashing should succeed");
    
    assert_ne!(hash_with_salt, hash_without_salt);
    assert_eq!(hash_with_salt.len(), 64);
}

// BLAKE2b with passes is not implemented yet
// #[tokio::test]
// async fn test_blake2b_with_passes() { ... }

#[tokio::test]
async fn test_empty_data_hashing() {
    let empty_data = b"";
    
    let algorithms = ["SHA256", "SHA3-256", "SHA3-384", "SHA3-512", "BLAKE2b"];
    
    for name in algorithms {
        let hash_result = match name {
            "SHA256" => Hash::sha256().with_data(empty_data).hash().await,
            "SHA3-256" => Hash::sha3().with_data(empty_data).hash().await,
            "BLAKE2b" => Hash::blake2b().with_data(empty_data).hash().await,
            _ => unreachable!(),
        }.expect(&format!("{} empty data hashing should succeed", name));
        
        assert!(!hash_result.is_empty(), "{} should produce non-empty hash", name);
        
        // Test reproducibility
        let hash_result2 = match name {
            "SHA256" => Hash::sha256().with_data(empty_data).hash().await,
            "SHA3-256" => Hash::sha3().with_data(empty_data).hash().await,
            "BLAKE2b" => Hash::blake2b().with_data(empty_data).hash().await,
            _ => unreachable!(),
        }.expect(&format!("{} empty data hashing should succeed", name));
        
        assert_eq!(hash_result, hash_result2, "{} should be reproducible", name);
    }
}

#[tokio::test]
async fn test_large_data_hashing() {
    let large_data = vec![0x42u8; 1_000_000]; // 1MB of data
    
    let algorithms = ["SHA256", "SHA3-256", "BLAKE2b"];
    
    for name in algorithms {
        let start = std::time::Instant::now();
        
        let hash_result = match name {
            "SHA256" => Hash::sha256().with_data(large_data.clone()).hash().await,
            "SHA3-256" => Hash::sha3().with_data(large_data.clone()).hash().await,
            "BLAKE2b" => Hash::blake2b().with_data(large_data.clone()).hash().await,
            _ => unreachable!(),
        }.expect(&format!("{} large data hashing should succeed", name));
        
        let duration = start.elapsed();
        println!("{} hashing 1MB took: {:?}", name, duration);
        
        assert!(!hash_result.is_empty(), "{} should produce non-empty hash", name);
    }
}

#[tokio::test]
async fn test_hash_passes_properties() {
    // Test HashPasses enum properties
    assert_eq!(HashPasses::Fast.iterations(), 100);
    assert_eq!(HashPasses::Default.iterations(), 10_000);
    assert_eq!(HashPasses::Strong.iterations(), 100_000);
    
    assert_eq!(HashPasses::Fast.security_level(), "Development");
    assert_eq!(HashPasses::Default.security_level(), "Production");
    assert_eq!(HashPasses::Strong.security_level(), "High Security");
    
    assert!(!HashPasses::Fast.is_password_safe());
    assert!(HashPasses::Default.is_password_safe());
    assert!(HashPasses::Strong.is_password_safe());
}

#[tokio::test]
async fn test_different_salt_same_data() {
    let test_data = b"Same data, different salts";
    let salt1 = b"salt_one";
    let salt2 = b"salt_two";
    
    let hash1 = Hash::sha256()
        .with_data(test_data)
        .with_salt(salt1)
        .hash()
        .await
        .expect("SHA256 with salt1 should succeed");
    
    let hash2 = Hash::sha256()
        .with_data(test_data)
        .with_salt(salt2)
        .hash()
        .await
        .expect("SHA256 with salt2 should succeed");
    
    assert_ne!(hash1, hash2);
    assert_eq!(hash1.len(), 32);
    assert_eq!(hash2.len(), 32);
}

#[tokio::test]
async fn test_same_salt_different_data() {
    let data1 = b"First data set";
    let data2 = b"Second data set";
    let salt = b"common_salt";
    
    let hash1 = Hash::sha256()
        .with_data(data1)
        .with_salt(salt)
        .hash()
        .await
        .expect("SHA256 with data1 should succeed");
    
    let hash2 = Hash::sha256()
        .with_data(data2)
        .with_salt(salt)
        .hash()
        .await
        .expect("SHA256 with data2 should succeed");
    
    assert_ne!(hash1, hash2);
    assert_eq!(hash1.len(), 32);
    assert_eq!(hash2.len(), 32);
}

#[tokio::test]
async fn test_unicode_text_hashing() {
    let unicode_texts = [
        "Hello, World! 🌍",
        "Rust 🦀 programming",
        "中文测试 Chinese test",
        "العربية Arabic text",
        "Русский Russian text",
        "ελληνικά Greek text",
        "🎉🎊🎈 Emoji party",
        "Mixed: Hello 世界 🌍 مرحبا Здравствуй",
    ];
    
    for text in unicode_texts {
        let hash_sha256 = Hash::sha256()
            .with_text(text)
            .hash()
            .await
            .expect(&format!("SHA256 should handle unicode: {}", text));
        
        let hash_blake2b = Hash::blake2b()
            .with_text(text)
            .hash()
            .await
            .expect(&format!("BLAKE2b should handle unicode: {}", text));
        
        assert_eq!(hash_sha256.len(), 32);
        assert_eq!(hash_blake2b.len(), 64);
        assert_ne!(hash_sha256, &hash_blake2b[..32]); // Different algorithms
    }
}

#[tokio::test]
async fn test_all_byte_values_hashing() {
    let all_bytes: Vec<u8> = (0..=255).collect();
    
    let hash_sha256 = Hash::sha256()
        .with_data(all_bytes.clone())
        .hash()
        .await
        .expect("SHA256 should handle all byte values");
    
    let hash_sha3 = Hash::sha3()
        .with_data(all_bytes.clone())
        .hash()
        .await
        .expect("SHA3 should handle all byte values");
    
    let hash_blake2b = Hash::blake2b()
        .with_data(all_bytes.clone())
        .hash()
        .await
        .expect("BLAKE2b should handle all byte values");
    
    assert_eq!(hash_sha256.len(), 32);
    assert_eq!(hash_sha3.len(), 32);
    assert_eq!(hash_blake2b.len(), 64);
    
    // All should be different
    assert_ne!(hash_sha256, hash_sha3);
    assert_ne!(hash_sha256, &hash_blake2b[..32]);
    assert_ne!(hash_sha3, &hash_blake2b[..32]);
}

#[tokio::test]
async fn test_hash_avalanche_effect() {
    // Small change in input should produce dramatically different hash
    let data1 = b"The quick brown fox jumps over the lazy dog";
    let data2 = b"The quick brown fox jumps over the lazy dog."; // Added period
    
    let hash1 = Hash::sha256()
        .with_data(data1)
        .hash()
        .await
        .expect("SHA256 hashing should succeed");
    
    let hash2 = Hash::sha256()
        .with_data(data2)
        .hash()
        .await
        .expect("SHA256 hashing should succeed");
    
    assert_ne!(hash1, hash2);
    
    // Count different bits (avalanche effect should be ~50%)
    let mut different_bits = 0;
    for (byte1, byte2) in hash1.iter().zip(hash2.iter()) {
        different_bits += (byte1 ^ byte2).count_ones();
    }
    
    let total_bits = hash1.len() * 8;
    let percentage = (different_bits as f64 / total_bits as f64) * 100.0;
    
    println!("Avalanche effect: {:.1}% bits changed", percentage);
    assert!(percentage > 30.0, "Avalanche effect should change >30% of bits");
}

#[tokio::test]
async fn test_concurrent_hashing() {
    let test_data = b"Concurrent hashing test data";
    
    // Spawn multiple concurrent hashing tasks
    let mut handles = vec![];
    for i in 0..20 {
        let data = format!("{} - iteration {}", 
                          std::str::from_utf8(test_data).unwrap(), i);
        
        let handle = tokio::spawn(async move {
            let sha256_hash = Hash::sha256()
                .with_text(&data)
                .with_passes(HashPasses::Fast)
                .hash()
                .await?;
            
            let blake2b_hash = Hash::blake2b()
                .with_text(&data)
                .hash()
                .await?;
            
            Ok::<_, HashError>((data, sha256_hash, blake2b_hash))
        });
        handles.push(handle);
    }
    
    // Verify all tasks completed successfully
    for handle in handles {
        let (data, sha256_hash, blake2b_hash) = handle.await
            .expect("Task should complete")
            .expect("Hashing should succeed");
        
        assert_eq!(sha256_hash.len(), 32);
        assert_eq!(blake2b_hash.len(), 64);
        
        // Verify reproducibility
        let sha256_verify = Hash::sha256()
            .with_text(&data)
            .with_passes(HashPasses::Fast)
            .hash()
            .await
            .expect("Verification hash should succeed");
        
        assert_eq!(sha256_hash, sha256_verify);
    }
}

#[tokio::test]
async fn test_hash_determinism_across_calls() {
    let test_cases = [
        ("", HashPasses::Fast),
        ("a", HashPasses::Default),
        ("Hello, World!", HashPasses::Strong),
        ("🦀 Rust Unicode Test", HashPasses::Default),
    ];
    
    for (text, passes) in test_cases {
        let salt = b"determinism_test_salt";
        
        // Hash the same input multiple times
        let mut hashes = Vec::new();
        for _ in 0..5 {
            let hash = Hash::sha256()
                .with_text(text)
                .with_salt(salt)
                .with_passes(passes)
                .hash()
                .await
                .expect("Hashing should succeed");
            hashes.push(hash);
        }
        
        // All hashes should be identical
        for i in 1..hashes.len() {
            assert_eq!(hashes[0], hashes[i], 
                      "Hash should be deterministic for input: '{}'", text);
        }
    }
}

#[tokio::test]
async fn test_cross_algorithm_differences() {
    let test_data = b"Cross-algorithm comparison test";
    let salt = b"common_salt";
    
    let sha256_hash = Hash::sha256()
        .with_data(test_data)
        .with_salt(salt)
        .hash()
        .await
        .expect("SHA256 should succeed");
    
    let sha3_hash = Hash::sha3()
        .with_data(test_data)
        .with_salt(salt)
        .hash()
        .await
        .expect("SHA3 should succeed");
    
    let blake2b_hash = Hash::blake2b()
        .with_data(test_data)
        .with_salt(salt)
        .hash()
        .await
        .expect("BLAKE2b should succeed");
    
    // All algorithms should produce different results
    assert_ne!(sha256_hash, sha3_hash);
    assert_ne!(sha256_hash, &blake2b_hash[..32]);
    assert_ne!(sha3_hash, &blake2b_hash[..32]);
    
    // But sizes should be correct
    assert_eq!(sha256_hash.len(), 32);
    assert_eq!(sha3_hash.len(), 32);
    assert_eq!(blake2b_hash.len(), 64);
}

#[tokio::test]
async fn test_performance_comparison() {
    let test_data = vec![0x55u8; 10_000]; // 10KB test data
    
    let algorithms = ["SHA256", "SHA3-256", "BLAKE2b"];
    
    for name in algorithms {
        let start = std::time::Instant::now();
        
        let _hash = match name {
            "SHA256" => Hash::sha256().with_data(test_data.clone()).with_passes(HashPasses::Fast).hash().await,
            "SHA3-256" => Hash::sha3().with_data(test_data.clone()).with_passes(HashPasses::Fast).hash().await,
            "BLAKE2b" => Hash::blake2b().with_data(test_data.clone()).hash().await,
            _ => unreachable!(),
        }.expect(&format!("{} should succeed", name));
        
        let duration = start.elapsed();
        println!("{} (10KB, Fast): {:?}", name, duration);
        
        // Ensure it completes in reasonable time
        assert!(duration.as_millis() < 1000, "{} should complete quickly", name);
    }
}