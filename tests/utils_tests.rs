//! Tests for cipher utility functions

use cyrup_crypt::{
    cipher::utils::*,
    CryptError,
};
use zeroize::Zeroizing;

#[test]
fn test_generate_nonce() {
    // Test basic nonce generation
    let nonce1 = generate_nonce(12);
    let nonce2 = generate_nonce(12);
    
    assert_eq!(nonce1.len(), 12);
    assert_eq!(nonce2.len(), 12);
    assert_ne!(nonce1, nonce2); // Should be different
    
    // Test different sizes
    let nonce_16 = generate_nonce(16);
    let nonce_24 = generate_nonce(24);
    let nonce_32 = generate_nonce(32);
    
    assert_eq!(nonce_16.len(), 16);
    assert_eq!(nonce_24.len(), 24);
    assert_eq!(nonce_32.len(), 32);
    
    // Test zero size
    let nonce_0 = generate_nonce(0);
    assert_eq!(nonce_0.len(), 0);
}

#[test]
fn test_generate_secure_nonce() {
    // Test secure nonce generation with zeroization
    let nonce1 = generate_secure_nonce(12);
    let nonce2 = generate_secure_nonce(12);
    
    assert_eq!(nonce1.len(), 12);
    assert_eq!(nonce2.len(), 12);
    assert_ne!(*nonce1, *nonce2); // Should be different
    
    // Test that it's actually Zeroizing type
    let _: Zeroizing<Vec<u8>> = nonce1;
}

#[test]
fn test_generate_nonce_array() {
    // Test fixed-size nonce array generation
    let nonce1: [u8; 16] = generate_nonce_array();
    let nonce2: [u8; 16] = generate_nonce_array();
    
    assert_ne!(nonce1, nonce2); // Should be different
    
    // Test different sizes
    let nonce_12: [u8; 12] = generate_nonce_array();
    let nonce_24: [u8; 24] = generate_nonce_array();
    
    assert_eq!(nonce_12.len(), 12);
    assert_eq!(nonce_24.len(), 24);
}

#[test]
fn test_secure_random_bytes() {
    // Test secure random bytes generation
    let bytes1 = secure_random_bytes(32).expect("Failed to generate 32 random bytes");
    let bytes2 = secure_random_bytes(32).expect("Failed to generate 32 random bytes");
    
    assert_eq!(bytes1.len(), 32);
    assert_eq!(bytes2.len(), 32);
    assert_ne!(*bytes1, *bytes2);
    
    // Test zero size
    let bytes_0 = secure_random_bytes(0).expect("Failed to generate 0 random bytes");
    assert_eq!(bytes_0.len(), 0);
    
    // Test large size
    let bytes_large = secure_random_bytes(1024 * 1024).expect("Failed to generate 1MB of random bytes");
    assert_eq!(bytes_large.len(), 1024 * 1024);
}

#[test]
fn test_constant_time_eq() {
    // Test equal arrays
    let a = b"hello";
    let b = b"hello";
    assert!(constant_time_eq(a, b));
    
    // Test different arrays
    let c = b"world";
    assert!(!constant_time_eq(a, c));
    
    // Test different lengths
    assert!(!constant_time_eq(a, &b"hello world"[..]));
    
    // Test empty arrays
    assert!(constant_time_eq(&[], &[]));
    
    // Test single byte differences
    let d = b"hellp"; // Last byte different
    assert!(!constant_time_eq(a, d));
    
    // Test all bytes different
    let e = b"HELLO";
    assert!(!constant_time_eq(a, e));
}

#[test]
fn test_pkcs7_padding() {
    // Test basic padding
    let data = b"hello";
    let padded = pad_pkcs7(data, 8);
    
    assert_eq!(padded.len(), 8);
    assert_eq!(&padded[..5], b"hello");
    assert_eq!(&padded[5..], &[3, 3, 3]);
    
    // Test unpadding
    let unpadded = unpad_pkcs7(&padded).expect("Failed to unpad PKCS7 padded data");
    assert_eq!(unpadded, data);
    
    // Test exact block size
    let data_exact = b"12345678";
    let padded_exact = pad_pkcs7(data_exact, 8);
    assert_eq!(padded_exact.len(), 16); // Should add full block of padding
    assert_eq!(&padded_exact[8..], &[8; 8]);
    
    let unpadded_exact = unpad_pkcs7(&padded_exact).expect("Failed to unpad PKCS7 exact block size data");
    assert_eq!(unpadded_exact, data_exact);
    
    // Test empty data
    let empty = b"";
    let padded_empty = pad_pkcs7(empty, 16);
    assert_eq!(padded_empty.len(), 16);
    assert_eq!(padded_empty, vec![16; 16]);
    
    let unpadded_empty = unpad_pkcs7(&padded_empty).expect("Failed to unpad PKCS7 empty data");
    assert_eq!(unpadded_empty, empty);
}

#[test]
fn test_unpad_pkcs7_errors() {
    // Test invalid padding - empty data
    let result = unpad_pkcs7(&[]);
    assert!(result.is_err());
    
    // Test invalid padding length - 0
    let invalid_zero = vec![1, 2, 3, 0];
    let result = unpad_pkcs7(&invalid_zero);
    assert!(result.is_err());
    
    // Test invalid padding length - too large
    let invalid_large = vec![1, 2, 3, 255];
    let result = unpad_pkcs7(&invalid_large);
    assert!(result.is_err());
    
    // Test inconsistent padding bytes
    let inconsistent = vec![1, 2, 3, 4, 5, 3, 2, 3]; // Should be 3, 3, 3
    let result = unpad_pkcs7(&inconsistent);
    assert!(result.is_err());
}

#[test]
fn test_xor_bytes() {
    // Test basic XOR
    let a = vec![0xFF, 0x00, 0xAA];
    let b = vec![0x00, 0xFF, 0x55];
    let result = xor_bytes(&a, &b);
    
    assert_eq!(result, vec![0xFF, 0xFF, 0xFF]);
    
    // Test XOR with itself = 0
    let c = vec![0x12, 0x34, 0x56];
    let result_self = xor_bytes(&c, &c);
    assert_eq!(result_self, vec![0x00, 0x00, 0x00]);
    
    // Test empty arrays
    let empty = xor_bytes(&[], &[]);
    assert_eq!(empty, vec![]);
}

#[test]
#[should_panic(expected = "XOR inputs must have equal length")]
fn test_xor_bytes_different_lengths() {
    let a = vec![1, 2, 3];
    let b = vec![1, 2];
    xor_bytes(&a, &b);
}

#[test]
fn test_derive_subkey() {
    let master_key = b"master-key-material";
    let info1 = b"context-1";
    let info2 = b"context-2";
    
    // Test basic key derivation
    let key1 = derive_subkey(master_key, info1, 32).expect("Failed to derive subkey with info1");
    let key2 = derive_subkey(master_key, info2, 32).expect("Failed to derive subkey with info2");
    
    assert_eq!(key1.len(), 32);
    assert_eq!(key2.len(), 32);
    assert_ne!(*key1, *key2); // Different contexts should produce different keys
    
    // Test same context produces same key
    let key1_again = derive_subkey(master_key, info1, 32).expect("Failed to derive subkey again with info1");
    assert_eq!(*key1, *key1_again);
    
    // Test different output lengths
    let key_16 = derive_subkey(master_key, info1, 16).expect("Failed to derive 16-byte subkey");
    let key_64 = derive_subkey(master_key, info1, 64).expect("Failed to derive 64-byte subkey");
    
    assert_eq!(key_16.len(), 16);
    assert_eq!(key_64.len(), 64);
    
    // First 16 bytes should match
    assert_eq!(&key_16[..], &key_64[..16]);
}

#[test]
fn test_derive_subkey_large_output() {
    let master_key = b"master";
    let info = b"info";
    
    // Test output larger than hash size (SHA256 = 32 bytes)
    let key_128 = derive_subkey(master_key, info, 128).expect("Failed to derive 128-byte subkey");
    assert_eq!(key_128.len(), 128);
    
    // Test very large output (multiple rounds)
    let key_1024 = derive_subkey(master_key, info, 1024).expect("Failed to derive 1024-byte subkey");
    assert_eq!(key_1024.len(), 1024);
}

#[test]
fn test_validate_key_size() {
    let key_32 = vec![0u8; 32];
    let key_16 = vec![0u8; 16];
    
    // Test valid key size
    validate_key_size(&key_32, 32, "AES-256").expect("Failed to validate 32-byte key for AES-256");
    validate_key_size(&key_16, 16, "AES-128").expect("Failed to validate 16-byte key for AES-128");
    
    // Test invalid key size
    let result = validate_key_size(&key_16, 32, "AES-256");
    assert!(result.is_err());
    
    match result {
        Err(CryptError::InvalidKeySize { expected, actual }) => {
            assert_eq!(expected, 32);
            assert_eq!(actual, 16);
        }
        _ => panic!("Expected InvalidKeySize error"),
    }
}

#[test]
fn test_validate_nonce_size() {
    let nonce_12 = vec![0u8; 12];
    let nonce_16 = vec![0u8; 16];
    
    // Test valid nonce size
    validate_nonce_size(&nonce_12, 12, "AES-GCM").expect("Failed to validate 12-byte nonce for AES-GCM");
    validate_nonce_size(&nonce_16, 16, "XChaCha20").expect("Failed to validate 16-byte nonce for XChaCha20");
    
    // Test invalid nonce size
    let result = validate_nonce_size(&nonce_16, 12, "AES-GCM");
    assert!(result.is_err());
    
    match result {
        Err(CryptError::InvalidNonceSize { expected, actual }) => {
            assert_eq!(expected, 12);
            assert_eq!(actual, 16);
        }
        _ => panic!("Expected InvalidNonceSize error"),
    }
}

#[test]
fn test_combine_slices() {
    // Test basic combination
    let a = b"hello";
    let b = b" ";
    let c = b"world";
    
    let combined = combine_slices(&[a, b, c]);
    assert_eq!(combined, b"hello world");
    
    // Test empty slices
    let empty_result = combine_slices(&[]);
    assert_eq!(empty_result, b"");
    
    // Test with empty elements
    let with_empty = combine_slices(&[a, &[], b, &[], c]);
    assert_eq!(with_empty, b"hello world");
    
    // Test single slice
    let single = combine_slices(&[a]);
    assert_eq!(single, b"hello");
}

#[test]
fn test_split_at_checked() {
    let data = b"hello world";
    
    // Test valid split
    let (first, second) = split_at_checked(data, 5).expect("Failed to split at position 5");
    assert_eq!(first, b"hello");
    assert_eq!(second, b" world");
    
    // Test split at start
    let (first, second) = split_at_checked(data, 0).expect("Failed to split at position 0");
    assert_eq!(first, b"");
    assert_eq!(second, b"hello world");
    
    // Test split at end
    let (first, second) = split_at_checked(data, 11).expect("Failed to split at position 11");
    assert_eq!(first, b"hello world");
    assert_eq!(second, b"");
    
    // Test out of bounds
    let result = split_at_checked(data, 20);
    assert!(result.is_err());
    
    match result {
        Err(CryptError::InvalidEncryptedData(msg)) => {
            assert!(msg.contains("exceeds data length"));
        }
        _ => panic!("Expected InvalidEncryptedData error"),
    }
}

#[test]
fn test_nonce_randomness() {
    // Generate many nonces and ensure they're unique
    let mut nonces = Vec::new();
    for _ in 0..100 {
        nonces.push(generate_nonce(12));
    }
    
    // Check all pairs are different
    for i in 0..nonces.len() {
        for j in (i + 1)..nonces.len() {
            assert_ne!(nonces[i], nonces[j], "Nonces {} and {} are identical", i, j);
        }
    }
}

#[test]
fn test_secure_random_bytes_uniqueness() {
    // Generate many random values and ensure they're unique
    let mut randoms = Vec::new();
    for _ in 0..50 {
        randoms.push(secure_random_bytes(32).expect("Failed to generate random bytes for uniqueness test"));
    }
    
    // Check all pairs are different
    for i in 0..randoms.len() {
        for j in (i + 1)..randoms.len() {
            assert_ne!(*randoms[i], *randoms[j], "Random values {} and {} are identical", i, j);
        }
    }
}