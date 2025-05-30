//! Unit tests for hashing functionality

use cryypt::prelude::*;

#[tokio::test]
async fn test_sha256_basic_hashing() -> Result<(), Box<dyn std::error::Error>> {
    let test_data = b"Hello, SHA-256!";
    
    let hash_result = Hash::sha256()
        .with_data(test_data)
        .hash()
        .await?;
    
    // SHA-256 always produces 32-byte (256-bit) hashes
    assert_eq!(hash_result.len(), 32);
    
    // Hash should be deterministic
    let hash_result2 = Hash::sha256()
        .with_data(test_data)
        .hash()
        .await?;
    
    assert_eq!(hash_result, hash_result2);
    
    Ok(())
}

#[tokio::test]
async fn test_sha256_with_text() -> Result<(), Box<dyn std::error::Error>> {
    let test_text = "Hello, SHA-256 text input!";
    
    let hash_result = Hash::sha256()
        .with_text(test_text)
        .hash()
        .await?;
    
    assert_eq!(hash_result.len(), 32);
    
    // Should be same as hashing the bytes directly
    let hash_result2 = Hash::sha256()
        .with_data(test_text.as_bytes())
        .hash()
        .await?;
    
    assert_eq!(hash_result, hash_result2);
    
    Ok(())
}

#[tokio::test]
async fn test_sha256_with_salt() -> Result<(), Box<dyn std::error::Error>> {
    let test_data = b"Hello, World!";
    let salt = b"random_salt";
    
    let hash_with_salt = Hash::sha256()
        .with_data(test_data)
        .with_salt(salt)
        .hash()
        .await?;
    
    // Hash without salt should be different
    let hash_without_salt = Hash::sha256()
        .with_data(test_data)
        .hash()
        .await?;
    
    assert_ne!(hash_with_salt, hash_without_salt);
    assert_eq!(hash_with_salt.len(), 32);
    
    Ok(())
}

#[tokio::test]
async fn test_sha256_with_multiple_passes() -> Result<(), Box<dyn std::error::Error>> {
    let test_data = b"Password123";
    let salt = b"unique_salt";
    
    let hash_1_pass = Hash::sha256()
        .with_data(test_data)
        .with_salt(salt)
        .with_passes(1)
        .hash()
        .await?;
    
    let hash_1000_passes = Hash::sha256()
        .with_data(test_data)
        .with_salt(salt)
        .with_passes(1000)
        .hash()
        .await?;
    
    // Different number of passes should produce different hashes
    assert_ne!(hash_1_pass, hash_1000_passes);
    assert_eq!(hash_1_pass.len(), 32);
    assert_eq!(hash_1000_passes.len(), 32);
    
    Ok(())
}

#[tokio::test]
async fn test_sha3_basic_hashing() -> Result<(), Box<dyn std::error::Error>> {
    let test_data = b"Hello, SHA-3!";
    
    let hash_result = Hash::sha3()
        .with_data(test_data)
        .hash()
        .await?;
    
    // SHA3-256 produces 32-byte hashes
    assert_eq!(hash_result.len(), 32);
    
    // Should be deterministic
    let hash_result2 = Hash::sha3()
        .with_data(test_data)
        .hash()
        .await?;
    
    assert_eq!(hash_result, hash_result2);
    
    Ok(())
}

#[tokio::test]
async fn test_sha3_vs_sha256() -> Result<(), Box<dyn std::error::Error>> {
    let test_data = b"Compare SHA-3 vs SHA-256";
    
    let sha3_hash = Hash::sha3()
        .with_data(test_data)
        .hash()
        .await?;
    
    let sha256_hash = Hash::sha256()
        .with_data(test_data)
        .hash()
        .await?;
    
    // Different algorithms should produce different hashes
    assert_ne!(sha3_hash, sha256_hash);
    assert_eq!(sha3_hash.len(), 32);
    assert_eq!(sha256_hash.len(), 32);
    
    Ok(())
}

#[tokio::test]
async fn test_sha3_with_salt_and_passes() -> Result<(), Box<dyn std::error::Error>> {
    let test_data = b"SHA-3 with salt and passes";
    let salt = b"sha3_salt";
    
    let hash_result = Hash::sha3()
        .with_data(test_data)
        .with_salt(salt)
        .with_passes(500)
        .hash()
        .await?;
    
    assert_eq!(hash_result.len(), 32);
    
    // Should be different from no salt/passes
    let plain_hash = Hash::sha3()
        .with_data(test_data)
        .hash()
        .await?;
    
    assert_ne!(hash_result, plain_hash);
    
    Ok(())
}

#[tokio::test]
async fn test_blake2b_basic_hashing() -> Result<(), Box<dyn std::error::Error>> {
    let test_data = b"Hello, Blake2b!";
    
    let hash_result = Hash::blake2b()
        .with_data(test_data)
        .hash()
        .await?;
    
    // Blake2b produces 64-byte (512-bit) hashes by default
    assert_eq!(hash_result.len(), 64);
    
    // Should be deterministic
    let hash_result2 = Hash::blake2b()
        .with_data(test_data)
        .hash()
        .await?;
    
    assert_eq!(hash_result, hash_result2);
    
    Ok(())
}

#[tokio::test]
async fn test_blake2b_vs_other_algorithms() -> Result<(), Box<dyn std::error::Error>> {
    let test_data = b"Compare Blake2b with others";
    
    let blake2b_hash = Hash::blake2b()
        .with_data(test_data)
        .hash()
        .await?;
    
    let sha256_hash = Hash::sha256()
        .with_data(test_data)
        .hash()
        .await?;
    
    let sha3_hash = Hash::sha3()
        .with_data(test_data)
        .hash()
        .await?;
    
    // All should be different
    assert_ne!(blake2b_hash[..32], sha256_hash);
    assert_ne!(blake2b_hash[..32], sha3_hash);
    assert_ne!(sha256_hash, sha3_hash);
    
    // Blake2b is longer
    assert_eq!(blake2b_hash.len(), 64);
    assert_eq!(sha256_hash.len(), 32);
    assert_eq!(sha3_hash.len(), 32);
    
    Ok(())
}

#[tokio::test]
async fn test_blake2b_with_salt() -> Result<(), Box<dyn std::error::Error>> {
    let test_data = b"Blake2b with salt test";
    let salt = b"blake2b_salt_key";
    
    let hash_with_salt = Hash::blake2b()
        .with_data(test_data)
        .with_salt(salt)
        .hash()
        .await?;
    
    let hash_without_salt = Hash::blake2b()
        .with_data(test_data)
        .hash()
        .await?;
    
    assert_ne!(hash_with_salt, hash_without_salt);
    assert_eq!(hash_with_salt.len(), 64);
    
    Ok(())
}

#[tokio::test]
async fn test_empty_data_hashing() -> Result<(), Box<dyn std::error::Error>> {
    let empty_data = b"";
    
    // Test all algorithms with empty data
    let sha256_empty = Hash::sha256()
        .with_data(empty_data)
        .hash()
        .await?;
    
    let sha3_empty = Hash::sha3()
        .with_data(empty_data)
        .hash()
        .await?;
    
    let blake2b_empty = Hash::blake2b()
        .with_data(empty_data)
        .hash()
        .await?;
    
    // Should still produce valid hashes
    assert_eq!(sha256_empty.len(), 32);
    assert_eq!(sha3_empty.len(), 32);
    assert_eq!(blake2b_empty.len(), 64);
    
    // Should be different from each other
    assert_ne!(sha256_empty, sha3_empty);
    assert_ne!(sha256_empty, blake2b_empty[..32]);
    assert_ne!(sha3_empty, blake2b_empty[..32]);
    
    Ok(())
}

#[tokio::test]
async fn test_large_data_hashing() -> Result<(), Box<dyn std::error::Error>> {
    // Create large data (1MB)
    let large_data: Vec<u8> = (0..1_000_000).map(|i| (i % 256) as u8).collect();
    
    let sha256_hash = Hash::sha256()
        .with_data(&large_data)
        .hash()
        .await?;
    
    let blake2b_hash = Hash::blake2b()
        .with_data(&large_data)
        .hash()
        .await?;
    
    assert_eq!(sha256_hash.len(), 32);
    assert_eq!(blake2b_hash.len(), 64);
    
    // Verify consistency with second hash
    let sha256_hash2 = Hash::sha256()
        .with_data(&large_data)
        .hash()
        .await?;
    
    assert_eq!(sha256_hash, sha256_hash2);
    
    Ok(())
}

#[tokio::test]
async fn test_unicode_text_hashing() -> Result<(), Box<dyn std::error::Error>> {
    let unicode_text = "Hello, 世界! 🌍 Émojis and spëcial châractérs";
    
    let sha256_hash = Hash::sha256()
        .with_text(unicode_text)
        .hash()
        .await?;
    
    let sha3_hash = Hash::sha3()
        .with_text(unicode_text)
        .hash()
        .await?;
    
    assert_eq!(sha256_hash.len(), 32);
    assert_eq!(sha3_hash.len(), 32);
    assert_ne!(sha256_hash, sha3_hash);
    
    // Should be same as hashing UTF-8 bytes
    let sha256_bytes = Hash::sha256()
        .with_data(unicode_text.as_bytes())
        .hash()
        .await?;
    
    assert_eq!(sha256_hash, sha256_bytes);
    
    Ok(())
}

#[tokio::test]
async fn test_different_salts_produce_different_hashes() -> Result<(), Box<dyn std::error::Error>> {
    let test_data = b"Same data, different salts";
    
    let hash1 = Hash::sha256()
        .with_data(test_data)
        .with_salt(b"salt1")
        .hash()
        .await?;
    
    let hash2 = Hash::sha256()
        .with_data(test_data)
        .with_salt(b"salt2")
        .hash()
        .await?;
    
    let hash3 = Hash::sha256()
        .with_data(test_data)
        .with_salt(b"")
        .hash()
        .await?;
    
    // All should be different
    assert_ne!(hash1, hash2);
    assert_ne!(hash1, hash3);
    assert_ne!(hash2, hash3);
    
    Ok(())
}

#[tokio::test]
async fn test_passes_deterministic() -> Result<(), Box<dyn std::error::Error>> {
    let test_data = b"Deterministic passes test";
    let salt = b"consistent_salt";
    
    // Same parameters should produce same result
    let hash1 = Hash::sha256()
        .with_data(test_data)
        .with_salt(salt)
        .with_passes(100)
        .hash()
        .await?;
    
    let hash2 = Hash::sha256()
        .with_data(test_data)
        .with_salt(salt)
        .with_passes(100)
        .hash()
        .await?;
    
    assert_eq!(hash1, hash2);
    
    // Different passes should produce different result
    let hash3 = Hash::sha256()
        .with_data(test_data)
        .with_salt(salt)
        .with_passes(101)
        .hash()
        .await?;
    
    assert_ne!(hash1, hash3);
    
    Ok(())
}

#[tokio::test]
async fn test_zero_passes() -> Result<(), Box<dyn std::error::Error>> {
    let test_data = b"Zero passes test";
    
    // Zero passes should work (equivalent to 1 pass)
    let hash_zero = Hash::sha256()
        .with_data(test_data)
        .with_passes(0)
        .hash()
        .await?;
    
    let hash_one = Hash::sha256()
        .with_data(test_data)
        .with_passes(1)
        .hash()
        .await?;
    
    assert_eq!(hash_zero.len(), 32);
    assert_eq!(hash_one.len(), 32);
    
    // They might be the same if 0 is treated as 1
    // This depends on implementation
    
    Ok(())
}

#[tokio::test]
async fn test_large_number_of_passes() -> Result<(), Box<dyn std::error::Error>> {
    let test_data = b"Large passes test";
    let salt = b"test_salt";
    
    // Test with large number of passes (but reasonable for testing)
    let hash_result = Hash::sha256()
        .with_data(test_data)
        .with_salt(salt)
        .with_passes(10000)
        .hash()
        .await?;
    
    assert_eq!(hash_result.len(), 32);
    
    // Should be different from single pass
    let single_pass = Hash::sha256()
        .with_data(test_data)
        .with_salt(salt)
        .with_passes(1)
        .hash()
        .await?;
    
    assert_ne!(hash_result, single_pass);
    
    Ok(())
}

#[tokio::test]
async fn test_binary_data_with_nulls() -> Result<(), Box<dyn std::error::Error>> {
    let binary_data = vec![0x00, 0x01, 0x02, 0x00, 0xFF, 0x00, 0xFE, 0xFD];
    
    let sha256_hash = Hash::sha256()
        .with_data(&binary_data)
        .hash()
        .await?;
    
    let blake2b_hash = Hash::blake2b()
        .with_data(&binary_data)
        .hash()
        .await?;
    
    assert_eq!(sha256_hash.len(), 32);
    assert_eq!(blake2b_hash.len(), 64);
    
    // Should be deterministic
    let sha256_hash2 = Hash::sha256()
        .with_data(&binary_data)
        .hash()
        .await?;
    
    assert_eq!(sha256_hash, sha256_hash2);
    
    Ok(())
}

#[tokio::test]
async fn test_concurrent_hashing() -> Result<(), Box<dyn std::error::Error>> {
    let test_data = b"Concurrent hashing test";
    
    // Hash the same data concurrently
    let futures = (0..10).map(|i| {
        let salt = format!("salt_{}", i);
        async move {
            Hash::sha256()
                .with_data(test_data)
                .with_salt(salt.as_bytes())
                .hash()
                .await
        }
    });
    
    let results: Vec<_> = futures::future::join_all(futures).await;
    
    // All should succeed
    for result in &results {
        assert!(result.is_ok());
        assert_eq!(result.as_ref().unwrap().len(), 32);
    }
    
    // All should be different due to different salts
    for i in 0..results.len() {
        for j in i+1..results.len() {
            assert_ne!(results[i].as_ref().unwrap(), results[j].as_ref().unwrap());
        }
    }
    
    Ok(())
}

#[tokio::test]
async fn test_hash_consistency_across_calls() -> Result<(), Box<dyn std::error::Error>> {
    let test_data = b"Consistency test data";
    let salt = b"consistency_salt";
    
    // Hash multiple times with same parameters
    let mut hashes = Vec::new();
    for _ in 0..5 {
        let hash = Hash::sha256()
            .with_data(test_data)
            .with_salt(salt)
            .with_passes(50)
            .hash()
            .await?;
        hashes.push(hash);
    }
    
    // All should be identical
    let first_hash = &hashes[0];
    for hash in &hashes {
        assert_eq!(hash, first_hash);
    }
    
    Ok(())
}

#[tokio::test]
async fn test_different_data_same_length() -> Result<(), Box<dyn std::error::Error>> {
    let data1 = b"12345678901234567890"; // 20 bytes
    let data2 = b"abcdefghijklmnopqrst"; // 20 bytes, different content
    
    let hash1 = Hash::sha256()
        .with_data(data1)
        .hash()
        .await?;
    
    let hash2 = Hash::sha256()
        .with_data(data2)
        .hash()
        .await?;
    
    // Same length, different content should produce different hashes
    assert_ne!(hash1, hash2);
    assert_eq!(hash1.len(), 32);
    assert_eq!(hash2.len(), 32);
    
    Ok(())
}

#[tokio::test]
async fn test_hash_output_non_zero() -> Result<(), Box<dyn std::error::Error>> {
    let test_data = b"Non-zero hash test";
    
    let sha256_hash = Hash::sha256()
        .with_data(test_data)
        .hash()
        .await?;
    
    let sha3_hash = Hash::sha3()
        .with_data(test_data)
        .hash()
        .await?;
    
    let blake2b_hash = Hash::blake2b()
        .with_data(test_data)
        .hash()
        .await?;
    
    // Hashes should not be all zeros (extremely unlikely but worth checking)
    assert!(sha256_hash.iter().any(|&b| b != 0));
    assert!(sha3_hash.iter().any(|&b| b != 0));
    assert!(blake2b_hash.iter().any(|&b| b != 0));
    
    Ok(())
}