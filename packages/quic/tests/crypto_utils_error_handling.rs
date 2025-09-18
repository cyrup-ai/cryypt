//! Tests for `crypto_utils` error handling - ensuring no panics occur

#![allow(clippy::unnested_or_patterns)]

use cryypt_quic::error::QuicError;
use cryypt_quic::protocols::messaging::*;

#[tokio::test]
async fn test_calculate_checksum_64_insufficient_data() {
    // Test with data that's too short (< 8 bytes)
    let short_data = vec![1, 2, 3, 4]; // Only 4 bytes

    let result = calculate_checksum_64(&short_data).await;

    assert!(result.is_err());
    match result {
        Err(QuicError::InsufficientCryptoData(msg)) => {
            assert!(msg.contains("insufficient bytes"));
        }
        _ => panic!("Expected InsufficientCryptoData error"),
    }
}

#[tokio::test]
async fn test_calculate_checksum_64_valid_data() {
    // Test with sufficient data (>= 8 bytes)
    let valid_data = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];

    let result = calculate_checksum_64(&valid_data).await;

    assert!(result.is_ok());
    let checksum = result.unwrap();
    assert!(checksum > 0); // Should return valid u64 checksum
}

#[tokio::test]
async fn test_calculate_authenticated_checksum_insufficient_data() {
    // Test with data that's too short
    let short_data = vec![1, 2, 3];
    let key = vec![0u8; 32]; // Valid key

    let result = calculate_authenticated_checksum(&short_data, &key).await;

    assert!(result.is_err());
    match result {
        Err(QuicError::InsufficientCryptoData(_)) => {
            // Expected error type
        }
        _ => panic!("Expected InsufficientCryptoData error"),
    }
}

#[tokio::test]
async fn test_calculate_authenticated_checksum_valid_data() {
    // Test with sufficient data
    let valid_data = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
    let key = vec![0u8; 32]; // Valid key

    let result = calculate_authenticated_checksum(&valid_data, &key).await;

    assert!(result.is_ok());
    let checksum = result.unwrap();
    assert_eq!(checksum.len(), 32); // Should return 32-byte HMAC
}

#[tokio::test]
async fn test_verify_authenticated_checksum_insufficient_data() {
    // Test verification with insufficient data
    let short_data = vec![1, 2];
    let key = vec![0u8; 32];
    let checksum = [0u8; 32];

    let result = verify_authenticated_checksum(&short_data, &key, &checksum).await;

    assert!(result.is_err());
    match result {
        Err(QuicError::InsufficientCryptoData(_)) => {
            // Expected error type
        }
        _ => panic!("Expected InsufficientCryptoData error"),
    }
}

#[tokio::test]
async fn test_derive_connection_key_insufficient_data() {
    // Test key derivation with insufficient data
    let short_conn_id = vec![1, 2, 3];
    let shared_secret = vec![0u8; 32];

    let result = derive_connection_key(&short_conn_id, &shared_secret).await;

    assert!(result.is_ok()); // Function should handle short conn_id gracefully
    let key = result.unwrap();
    assert_eq!(key.len(), 32); // Should return 32-byte key regardless
}

#[tokio::test]
async fn test_derive_connection_key_valid_data() {
    // Test key derivation with sufficient data
    let valid_conn_id = vec![0u8; 16]; // Standard connection ID length
    let shared_secret = vec![0u8; 32]; // Standard secret length

    let result = derive_connection_key(&valid_conn_id, &shared_secret).await;

    assert!(result.is_ok());
    let key = result.unwrap();
    assert_eq!(key.len(), 32); // Should return 32-byte key
}

#[tokio::test]
async fn test_hash_failure_error_propagation() {
    // Test that hash failures are properly propagated as errors
    let empty_data = vec![];

    let result = calculate_checksum_64(&empty_data).await;

    assert!(result.is_err());
    // Should get either HashFailure or InsufficientCryptoData
    match result {
        Err(QuicError::HashFailure(_)) | Err(QuicError::InsufficientCryptoData(_)) => {
            // Both are acceptable error types for this case
        }
        _ => panic!("Expected hash-related error"),
    }
}
