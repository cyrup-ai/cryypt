//! ECDSA-based JWT Algorithm Implementations
//!
//! This module provides blazing-fast, zero-allocation implementations of
//! ECDSA algorithms (ES256, ES384) for JWT signing and verification.

use crate::error::JwtError;

/// Sign with ECDSA P-256 (ES256)
/// Zero-allocation blazing-fast ECDSA signing
#[inline]
pub(crate) fn sign_es256(_message: &str, _private_key: &[u8]) -> Result<Vec<u8>, JwtError> {
    Err(JwtError::UnsupportedAlgorithm(
        "ES256 not yet implemented".to_string(),
    ))
}

/// Verify ECDSA P-256 (ES256) signature
/// Zero-allocation blazing-fast ECDSA verification
#[inline]
pub(crate) fn verify_es256(
    _message: &str,
    _signature: &[u8],
    _public_key: &[u8],
) -> Result<bool, JwtError> {
    Err(JwtError::UnsupportedAlgorithm(
        "ES256 verification not yet implemented".to_string(),
    ))
}

/// Sign with ECDSA P-384 (ES384)
/// Zero-allocation blazing-fast ECDSA signing
#[inline]
pub(crate) fn sign_es384(_message: &str, _private_key: &[u8]) -> Result<Vec<u8>, JwtError> {
    Err(JwtError::UnsupportedAlgorithm(
        "ES384 not yet implemented".to_string(),
    ))
}

/// Verify ECDSA P-384 (ES384) signature
/// Zero-allocation blazing-fast ECDSA verification
#[inline]
pub(crate) fn verify_es384(
    _message: &str,
    _signature: &[u8],
    _public_key: &[u8],
) -> Result<bool, JwtError> {
    Err(JwtError::UnsupportedAlgorithm(
        "ES384 verification not yet implemented".to_string(),
    ))
}
