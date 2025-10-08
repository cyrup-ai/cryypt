//! Internal hash functions using direct async - NO threading needed for fast hash operations!

use crate::{HashResult, Result};

/// Internal SHA-256 hash function - Direct async implementation
///
/// # Errors
///
/// This function is infallible for valid input data and should not return errors
/// under normal circumstances.
pub async fn sha256_hash(data: &[u8]) -> Result<HashResult> {
    // Direct async implementation - SHA-256 is fast, no threading needed
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();

    // Yield to allow other async tasks to run
    tokio::task::yield_now().await;

    Ok(HashResult::new(result.to_vec()))
}

/// Internal SHA3-256 hash function - Direct async implementation
///
/// # Errors
///
/// This function is infallible for valid input data and should not return errors
/// under normal circumstances.
pub async fn sha3_256_hash(data: &[u8]) -> Result<HashResult> {
    // Direct async implementation - SHA3-256 is fast, no threading needed
    use sha3::{Digest, Sha3_256};

    let mut hasher = Sha3_256::new();
    hasher.update(data);
    let result = hasher.finalize();

    // Yield to allow other async tasks to run
    tokio::task::yield_now().await;

    Ok(HashResult::new(result.to_vec()))
}

/// Internal SHA3-384 hash function - Direct async implementation
///
/// # Errors
///
/// This function is infallible for valid input data and should not return errors
/// under normal circumstances.
pub async fn sha3_384_hash(data: &[u8]) -> Result<HashResult> {
    // Direct async implementation - SHA3-384 is fast, no threading needed
    use sha3::{Digest, Sha3_384};

    let mut hasher = Sha3_384::new();
    hasher.update(data);
    let result = hasher.finalize();

    // Yield to allow other async tasks to run
    tokio::task::yield_now().await;

    Ok(HashResult::new(result.to_vec()))
}

/// Internal SHA3-512 hash function - Direct async implementation
///
/// # Errors
///
/// This function is infallible for valid input data and should not return errors
/// under normal circumstances.
pub async fn sha3_512_hash(data: &[u8]) -> Result<HashResult> {
    // Direct async implementation - SHA3-512 is fast, no threading needed
    use sha3::{Digest, Sha3_512};

    let mut hasher = Sha3_512::new();
    hasher.update(data);
    let result = hasher.finalize();

    // Yield to allow other async tasks to run
    tokio::task::yield_now().await;

    Ok(HashResult::new(result.to_vec()))
}

/// Internal Blake2b hash function - Direct async implementation
///
/// # Errors
///
/// This function is infallible for valid input data and should not return errors
/// under normal circumstances.
pub async fn blake2b_hash(data: &[u8]) -> Result<HashResult> {
    // Direct async implementation - Blake2b is fast, no threading needed
    use blake2::{Blake2b512, Digest};

    let mut hasher = Blake2b512::new();
    hasher.update(data);
    let result = hasher.finalize();

    // Yield to allow other async tasks to run
    tokio::task::yield_now().await;

    Ok(HashResult::new(result.to_vec()))
}

/// Internal Blake2b hash function with custom size - Direct async implementation
///
/// # Errors
///
/// This function is infallible for valid input data and should not return errors
/// under normal circumstances.
pub async fn blake2b_hash_with_size(data: &[u8], output_size: usize) -> Result<HashResult> {
    // Direct async implementation - Blake2b is fast, no threading needed
    use blake2::{Blake2b512, Digest};

    let mut hasher = Blake2b512::new();
    hasher.update(data);
    let result = hasher.finalize();

    // Truncate to requested size
    let truncated = result[..output_size.min(64)].to_vec();

    // Yield to allow other async tasks to run
    tokio::task::yield_now().await;

    Ok(HashResult::new(truncated))
}

/// Internal SHA-256 HMAC function - Direct async implementation
///
/// # Errors
///
/// Returns `HashError::Internal` if the HMAC key is invalid or the HMAC operation fails.
pub async fn sha256_hmac(data: &[u8], key: &[u8]) -> Result<HashResult> {
    // Direct async implementation - HMAC is fast, no threading needed
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    type HmacSha256 = Hmac<Sha256>;

    let mut mac = HmacSha256::new_from_slice(key)
        .map_err(|e| crate::HashError::internal(format!("HMAC key error: {e}")))?;

    mac.update(data);
    let result = mac.finalize().into_bytes();

    // Yield to allow other async tasks to run
    tokio::task::yield_now().await;

    Ok(HashResult::new(result.to_vec()))
}
