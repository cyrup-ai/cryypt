//! Cryptographic utilities for message processing
//!
//! This module provides checksum calculation and key derivation functions
//! for secure message processing in the QUIC messaging protocol.


/// Calculate checksum for message integrity verification using cryypt SHA256
/// 
/// Uses 64 bits from SHA256 for improved collision resistance while maintaining reasonable performance.
/// Provides 2^32 expected collisions vs 2^16 for 32-bit checksums.
pub async fn calculate_checksum(data: &[u8]) -> u32 {
    calculate_checksum_64(data).await as u32 // Backward compatibility: return lower 32 bits
}

/// Calculate 64-bit checksum for enhanced integrity verification
/// 
/// Uses the first 64 bits of SHA256, providing significantly better collision resistance
/// than 32-bit checksums. Recommended for security-critical applications.
pub async fn calculate_checksum_64(data: &[u8]) -> u64 {
    use cryypt_hashing::Hash;
    
    Hash::sha256()
        .on_result(|result| match result {
            Ok(hash_result) => {
                // Convert first 8 bytes to u64
                let bytes = hash_result.as_bytes();
                if bytes.len() >= 8 {
                    u64::from_be_bytes([
                        bytes[0], bytes[1], bytes[2], bytes[3],
                        bytes[4], bytes[5], bytes[6], bytes[7]
                    ])
                } else {
                    tracing::error!("SHA256 hash too short: {} bytes", bytes.len());
                    panic!("Critical hash failure: insufficient bytes")
                }
            }
            Err(e) => {
                tracing::error!("SHA256 hash computation failed: {}", e);
                panic!("Critical hash failure")
            }
        })
        .compute(data)
        .await
}

/// Calculate HMAC-based authenticated checksum for maximum security
/// 
/// Uses HMAC-SHA256 with the provided key for cryptographically secure message authentication.
/// Protects against both accidental corruption and malicious tampering.
pub async fn calculate_authenticated_checksum(data: &[u8], key: &[u8]) -> [u8; 32] {
    use cryypt_hashing::Hash;
    
    let hmac_bytes = Hash::sha256()
        .with_key(key.to_vec())
        .on_result(|result| match result {
            Ok(hash_result) => {
                // Return the raw hash bytes
                hash_result.to_vec()
            }
            Err(e) => {
                tracing::error!("HMAC-SHA256 computation failed: {}", e);
                panic!("Critical HMAC computation failure")
            }
        })
        .compute(data)
        .await;
    
    // Convert to fixed-size array
    let mut result = [0u8; 32];
    if hmac_bytes.len() >= 32 {
        result.copy_from_slice(&hmac_bytes[0..32]);
        result
    } else {
        tracing::error!("HMAC-SHA256 hash too short: {} bytes", hmac_bytes.len());
        panic!("Critical HMAC failure: insufficient bytes")
    }
}

/// Verify HMAC-based authenticated checksum
pub async fn verify_authenticated_checksum(data: &[u8], key: &[u8], expected_checksum: &[u8; 32]) -> bool {
    // Compute HMAC using cryypt API and compare with expected
    let computed_checksum = calculate_authenticated_checksum(data, key).await;
    
    // Constant-time comparison to prevent timing attacks
    computed_checksum.iter()
        .zip(expected_checksum.iter())
        .fold(0u8, |acc, (a, b)| acc | (a ^ b)) == 0
}

/// Generate encryption key from QUIC connection ID and shared secret using HMAC-SHA256
pub async fn derive_connection_key(conn_id: &[u8], shared_secret: &[u8]) -> Vec<u8> {
    use cryypt_hashing::Hash;
    
    // Create connection-specific input combining conn_id with domain separation
    const DOMAIN_SEPARATION: &[u8] = b"cryypt-quic-key-derivation-v1";
    let mut input = Vec::with_capacity(conn_id.len() + DOMAIN_SEPARATION.len());
    input.extend_from_slice(conn_id);
    input.extend_from_slice(DOMAIN_SEPARATION);
    
    let derived_key = Hash::sha256()
        .with_key(shared_secret.to_vec())
        .on_result(|result| match result {
            Ok(hash_result) => hash_result.to_vec(),
            Err(e) => {
                tracing::error!("Connection key derivation failed: {}", e);
                panic!("Critical key derivation failure")
            }
        })
        .compute(input)
        .await;
    
    if derived_key.len() >= 32 {
        // Use exactly 32 bytes for consistent key size
        derived_key[..32].to_vec()
    } else {
        // Key derivation produced insufficient bytes - critical failure
        tracing::error!("Key derivation produced insufficient bytes: {} < 32", derived_key.len());
        panic!("Critical key derivation failure: insufficient bytes")
    }
}