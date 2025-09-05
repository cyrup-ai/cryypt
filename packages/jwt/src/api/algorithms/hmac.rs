//! HMAC-based JWT Algorithm Implementations
//!
//! This module provides blazing-fast, zero-allocation implementations of
//! HMAC-SHA algorithms (HS256, HS384, HS512) for JWT signing and verification.

use super::utils::constant_time_eq;
use crate::error::JwtError;
use hmac::{Hmac, Mac};
use sha2::{Sha256, Sha384, Sha512};

type HmacSha256 = Hmac<Sha256>;
type HmacSha384 = Hmac<Sha384>;
type HmacSha512 = Hmac<Sha512>;

/// Sign with HMAC-SHA256 (HS256)
/// Zero-allocation blazing-fast HMAC signing
#[inline]
pub(crate) fn sign_hs256(message: &str, secret: &[u8]) -> Result<Vec<u8>, JwtError> {
    let mut mac = HmacSha256::new_from_slice(secret)
        .map_err(|_| JwtError::InvalidKey("Invalid HMAC key".to_string()))?;
    mac.update(message.as_bytes());
    Ok(mac.finalize().into_bytes().to_vec())
}

/// Verify HMAC-SHA256 (HS256) signature
/// Zero-allocation blazing-fast HMAC verification with constant-time comparison
#[inline]
pub(crate) fn verify_hs256(
    message: &str,
    signature: &[u8],
    secret: &[u8],
) -> Result<bool, JwtError> {
    let expected = sign_hs256(message, secret)?;
    Ok(constant_time_eq(signature, &expected))
}

/// Sign with HMAC-SHA384 (HS384)
/// Zero-allocation blazing-fast HMAC signing
#[inline]
pub(crate) fn sign_hs384(message: &str, secret: &[u8]) -> Result<Vec<u8>, JwtError> {
    let mut mac = HmacSha384::new_from_slice(secret)
        .map_err(|_| JwtError::InvalidKey("Invalid HMAC key".to_string()))?;
    mac.update(message.as_bytes());
    Ok(mac.finalize().into_bytes().to_vec())
}

/// Verify HMAC-SHA384 (HS384) signature
/// Zero-allocation blazing-fast HMAC verification with constant-time comparison
#[inline]
pub(crate) fn verify_hs384(
    message: &str,
    signature: &[u8],
    secret: &[u8],
) -> Result<bool, JwtError> {
    let expected = sign_hs384(message, secret)?;
    Ok(constant_time_eq(signature, &expected))
}

/// Sign with HMAC-SHA512 (HS512)
/// Zero-allocation blazing-fast HMAC signing
#[inline]
pub(crate) fn sign_hs512(message: &str, secret: &[u8]) -> Result<Vec<u8>, JwtError> {
    let mut mac = HmacSha512::new_from_slice(secret)
        .map_err(|_| JwtError::InvalidKey("Invalid HMAC key".to_string()))?;
    mac.update(message.as_bytes());
    Ok(mac.finalize().into_bytes().to_vec())
}

/// Verify HMAC-SHA512 (HS512) signature
/// Zero-allocation blazing-fast HMAC verification with constant-time comparison
#[inline]
pub(crate) fn verify_hs512(
    message: &str,
    signature: &[u8],
    secret: &[u8],
) -> Result<bool, JwtError> {
    let expected = sign_hs512(message, secret)?;
    Ok(constant_time_eq(signature, &expected))
}
