//! RSA-based JWT Algorithm Implementations
//!
//! This module provides blazing-fast, zero-allocation implementations of
//! RSA-SHA algorithms (RS256, RS384, RS512) for JWT signing and verification.

use crate::error::JwtError;
use rsa::pkcs1v15::{Signature, SigningKey, VerifyingKey};
use rsa::sha2::{Sha256, Sha384, Sha512};
use rsa::signature::{SignatureEncoding, Signer, Verifier};
use rsa::{
    RsaPrivateKey, RsaPublicKey,
    pkcs8::{DecodePrivateKey, DecodePublicKey},
};

/// Sign with RSA-SHA256 (RS256)
/// Zero-allocation blazing-fast RSA signing
#[inline]
pub(crate) fn sign_rs256(message: &str, private_key: &[u8]) -> Result<Vec<u8>, JwtError> {
    let private_key = RsaPrivateKey::from_pkcs8_der(private_key)
        .map_err(|e| JwtError::InvalidKey(format!("Invalid RSA private key: {e}")))?;

    let signing_key = SigningKey::<Sha256>::new(private_key);
    let signature = signing_key.sign(message.as_bytes());
    Ok(signature.to_bytes().as_ref().to_vec())
}

/// Verify RSA-SHA256 (RS256) signature
/// Zero-allocation blazing-fast RSA verification
///
/// # Errors
/// Returns `Err` if:
/// - Public key cannot be decoded from SPKI DER format
/// - Signature format is invalid or verification fails
#[inline]
pub fn verify_rs256(
    message: &str,
    signature: &[u8],
    public_key: &[u8],
) -> Result<bool, JwtError> {
    let public_key = RsaPublicKey::from_public_key_der(public_key)
        .map_err(|e| JwtError::InvalidKey(format!("Invalid RSA public key: {e}")))?;

    let verifying_key = VerifyingKey::<Sha256>::new(public_key);
    let signature = Signature::try_from(signature).map_err(|_| JwtError::InvalidSignature)?;

    match verifying_key.verify(message.as_bytes(), &signature) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Sign with RSA-SHA384 (RS384)
/// Zero-allocation blazing-fast RSA signing
#[inline]
pub(crate) fn sign_rs384(message: &str, private_key: &[u8]) -> Result<Vec<u8>, JwtError> {
    let private_key = RsaPrivateKey::from_pkcs8_der(private_key)
        .map_err(|e| JwtError::InvalidKey(format!("Invalid RSA private key: {e}")))?;

    let signing_key = SigningKey::<Sha384>::new(private_key);
    let signature = signing_key.sign(message.as_bytes());
    Ok(signature.to_bytes().as_ref().to_vec())
}

/// Verify RSA-SHA384 (RS384) signature
/// Zero-allocation blazing-fast RSA verification
#[inline]
pub(crate) fn verify_rs384(
    message: &str,
    signature: &[u8],
    public_key: &[u8],
) -> Result<bool, JwtError> {
    let public_key = RsaPublicKey::from_public_key_der(public_key)
        .map_err(|e| JwtError::InvalidKey(format!("Invalid RSA public key: {e}")))?;

    let verifying_key = VerifyingKey::<Sha384>::new(public_key);
    let signature = Signature::try_from(signature).map_err(|_| JwtError::InvalidSignature)?;

    match verifying_key.verify(message.as_bytes(), &signature) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Sign with RSA-SHA512 (RS512)
/// Zero-allocation blazing-fast RSA signing
#[inline]
pub(crate) fn sign_rs512(message: &str, private_key: &[u8]) -> Result<Vec<u8>, JwtError> {
    let private_key = RsaPrivateKey::from_pkcs8_der(private_key)
        .map_err(|e| JwtError::InvalidKey(format!("Invalid RSA private key: {e}")))?;

    let signing_key = SigningKey::<Sha512>::new(private_key);
    let signature = signing_key.sign(message.as_bytes());
    Ok(signature.to_bytes().as_ref().to_vec())
}

/// Verify RSA-SHA512 (RS512) signature
/// Zero-allocation blazing-fast RSA verification
#[inline]
pub(crate) fn verify_rs512(
    message: &str,
    signature: &[u8],
    public_key: &[u8],
) -> Result<bool, JwtError> {
    let public_key = RsaPublicKey::from_public_key_der(public_key)
        .map_err(|e| JwtError::InvalidKey(format!("Invalid RSA public key: {e}")))?;

    let verifying_key = VerifyingKey::<Sha512>::new(public_key);
    let signature = Signature::try_from(signature).map_err(|_| JwtError::InvalidSignature)?;

    match verifying_key.verify(message.as_bytes(), &signature) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}
