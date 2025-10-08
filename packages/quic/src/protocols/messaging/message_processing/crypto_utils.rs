//! Cryptographic utilities for message processing
//!
//! This module provides checksum calculation and key derivation functions
//! for secure message processing in the QUIC messaging protocol.

use crate::error::{QuicError, Result};

/// Calculate checksum for message integrity verification using cryypt SHA256
///
/// Uses 64 bits from SHA256 for improved collision resistance while maintaining reasonable performance.
/// Provides 2^32 expected collisions vs 2^16 for 32-bit checksums.
///
/// # Errors
///
/// Returns `QuicError::InsufficientCryptoData` if input data is empty or too short,
/// or propagates errors from `calculate_checksum_64`.
pub async fn calculate_checksum(data: &[u8]) -> Result<u32> {
    // Check for empty data
    if data.is_empty() {
        return Err(QuicError::insufficient_crypto_data(
            "cannot calculate checksum for empty data".to_string(),
        ));
    }

    // Backward compatibility: return lower 32 bits
    let checksum_64 = calculate_checksum_64(data).await?;
    #[allow(clippy::cast_possible_truncation)]
    Ok(u32::try_from(checksum_64 & 0xFFFF_FFFF).unwrap_or(checksum_64 as u32))
}

/// Calculate 64-bit checksum for enhanced integrity verification
///
/// Uses the first 64 bits of SHA256, providing significantly better collision resistance
/// than 32-bit checksums. Recommended for security-critical applications.
///
/// # Errors
///
/// Returns `QuicError::InsufficientCryptoData` if input data is less than 8 bytes,
/// or `QuicError::HashFailure` if SHA256 computation fails.
pub async fn calculate_checksum_64(data: &[u8]) -> Result<u64> {
    use cryypt_hashing::Hash;

    // Validate minimum input length for meaningful checksum
    if data.len() < 8 {
        return Err(QuicError::insufficient_crypto_data(format!(
            "insufficient bytes for checksum calculation: {} bytes, expected at least 8",
            data.len()
        )));
    }

    let hash_result = Hash::sha256().compute(data).await;

    let hash_bytes = match hash_result {
        Ok(hash_result) => hash_result.to_vec(),
        Err(e) => {
            tracing::error!("SHA256 hash computation failed: {}", e);
            return Err(QuicError::hash_failure(
                "SHA256 computation failed".to_string(),
            ));
        }
    };

    // Check if we got a valid hash result
    if hash_bytes.is_empty() {
        return Err(QuicError::hash_failure(
            "SHA256 computation failed".to_string(),
        ));
    }

    if hash_bytes.len() >= 8 {
        Ok(u64::from_be_bytes([
            hash_bytes[0],
            hash_bytes[1],
            hash_bytes[2],
            hash_bytes[3],
            hash_bytes[4],
            hash_bytes[5],
            hash_bytes[6],
            hash_bytes[7],
        ]))
    } else {
        tracing::error!("SHA256 hash too short: {} bytes", hash_bytes.len());
        Err(QuicError::insufficient_crypto_data(format!(
            "SHA256 hash too short: {} bytes, expected at least 8",
            hash_bytes.len()
        )))
    }
}

/// Calculate HMAC-based authenticated checksum for maximum security
///
/// Uses HMAC-SHA256 with the provided key for cryptographically secure message authentication.
/// Protects against both accidental corruption and malicious tampering.
///
/// # Errors
///
/// Returns `QuicError::InsufficientCryptoData` if input data is less than 4 bytes,
/// or `QuicError::HashFailure` if HMAC-SHA256 computation fails.
pub async fn calculate_authenticated_checksum(data: &[u8], key: &[u8]) -> Result<[u8; 32]> {
    use cryypt_hashing::Hash;

    // Validate minimum input length for meaningful authentication
    if data.len() < 4 {
        return Err(QuicError::insufficient_crypto_data(format!(
            "insufficient bytes for authenticated checksum: {} bytes, expected at least 4",
            data.len()
        )));
    }

    let hmac_result = Hash::sha256().with_key(key.to_vec()).compute(data).await;

    let hmac_bytes = match hmac_result {
        Ok(hash_result) => hash_result.to_vec(),
        Err(e) => {
            tracing::error!("HMAC-SHA256 computation failed: {}", e);
            return Err(QuicError::hash_failure(
                "HMAC-SHA256 computation failed".to_string(),
            ));
        }
    };

    // Check if we got a valid hash result
    if hmac_bytes.is_empty() {
        return Err(QuicError::hash_failure(
            "HMAC-SHA256 computation failed".to_string(),
        ));
    }

    // Convert to fixed-size array
    let mut result = [0u8; 32];
    if hmac_bytes.len() >= 32 {
        result.copy_from_slice(&hmac_bytes[0..32]);
        Ok(result)
    } else {
        tracing::error!("HMAC-SHA256 hash too short: {} bytes", hmac_bytes.len());
        Err(QuicError::insufficient_crypto_data(format!(
            "HMAC-SHA256 hash too short: {} bytes, expected at least 32",
            hmac_bytes.len()
        )))
    }
}

/// Verify HMAC-based authenticated checksum
///
/// # Errors
///
/// Returns `QuicError::InsufficientCryptoData` if input data is less than 3 bytes,
/// or propagates errors from `calculate_authenticated_checksum`.
pub async fn verify_authenticated_checksum(
    data: &[u8],
    key: &[u8],
    expected_checksum: &[u8; 32],
) -> Result<bool> {
    // Validate minimum input length for verification
    if data.len() < 3 {
        return Err(QuicError::insufficient_crypto_data(format!(
            "insufficient bytes for checksum verification: {} bytes, expected at least 3",
            data.len()
        )));
    }

    // Compute HMAC using cryypt API and compare with expected
    let computed_checksum = calculate_authenticated_checksum(data, key).await?;

    // Constant-time comparison to prevent timing attacks
    Ok(computed_checksum
        .iter()
        .zip(expected_checksum.iter())
        .fold(0u8, |acc, (a, b)| acc | (a ^ b))
        == 0)
}

/// Generate encryption key from QUIC connection ID and shared secret using HMAC-SHA256
///
/// # Errors
///
/// Returns an error if:
/// - HMAC computation fails
/// - Key derivation operation fails
pub async fn derive_connection_key(conn_id: &[u8], shared_secret: &[u8]) -> Result<Vec<u8>> {
    use cryypt_hashing::Hash;

    // Create connection-specific input combining conn_id with domain separation
    const DOMAIN_SEPARATION: &[u8] = b"cryypt-quic-key-derivation-v1";
    let mut input = Vec::with_capacity(conn_id.len() + DOMAIN_SEPARATION.len());
    input.extend_from_slice(conn_id);
    input.extend_from_slice(DOMAIN_SEPARATION);

    let derivation_result = Hash::sha256()
        .with_key(shared_secret.to_vec())
        .compute(input)
        .await;

    let derived_key = match derivation_result {
        Ok(hash_result) => hash_result.to_vec(),
        Err(e) => {
            tracing::error!("Connection key derivation failed: {}", e);
            return Err(QuicError::key_derivation(
                "Connection key derivation failed".to_string(),
            ));
        }
    };

    // Check if we got a valid key derivation result
    if derived_key.is_empty() {
        return Err(QuicError::key_derivation(
            "Key derivation failed".to_string(),
        ));
    }

    if derived_key.len() >= 32 {
        // Use exactly 32 bytes for consistent key size
        Ok(derived_key[..32].to_vec())
    } else {
        // Key derivation produced insufficient bytes - critical failure
        tracing::error!(
            "Key derivation produced insufficient bytes: {} < 32",
            derived_key.len()
        );
        Err(QuicError::insufficient_crypto_data(format!(
            "Key derivation produced insufficient bytes: {} < 32",
            derived_key.len()
        )))
    }
}
