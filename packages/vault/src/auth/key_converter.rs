//! RSA key format conversion utilities
//!
//! Converts between PKCS1 (from cryypt_key) and PKCS8/SPKI (for JWT algorithms)

use crate::error::{VaultError, VaultResult};
use rsa::pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey};
use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey};
use rsa::{RsaPrivateKey, RsaPublicKey};

/// Convert PKCS1 DER private key to PKCS8 DER format
///
/// # Arguments
/// * `pkcs1_der` - Private key in PKCS1 DER format (from RsaKeyBuilder)
///
/// # Returns
/// Private key in PKCS8 DER format (for RS256 signing)
pub fn pkcs1_to_pkcs8(pkcs1_der: &[u8]) -> VaultResult<Vec<u8>> {
    // Parse PKCS1 private key
    let private_key = RsaPrivateKey::from_pkcs1_der(pkcs1_der).map_err(|e| {
        VaultError::Crypto(format!("Failed to parse PKCS1 private key: {}", e))
    })?;

    // Encode to PKCS8
    let pkcs8_der = private_key
        .to_pkcs8_der()
        .map_err(|e| VaultError::Crypto(format!("Failed to encode PKCS8 private key: {}", e)))?;

    Ok(pkcs8_der.as_bytes().to_vec())
}

/// Convert PKCS1 DER public key to SPKI DER format
///
/// # Arguments
/// * `pkcs1_der` - Public key in PKCS1 DER format (from RsaKeyBuilder)
///
/// # Returns
/// Public key in SPKI DER format (for RS256 verification)
pub fn pkcs1_public_to_spki(pkcs1_der: &[u8]) -> VaultResult<Vec<u8>> {
    // Parse PKCS1 public key
    let public_key = RsaPublicKey::from_pkcs1_der(pkcs1_der).map_err(|e| {
        VaultError::Crypto(format!("Failed to parse PKCS1 public key: {}", e))
    })?;

    // Encode to SPKI
    let spki_der = public_key.to_public_key_der().map_err(|e| {
        VaultError::Crypto(format!("Failed to encode SPKI public key: {}", e))
    })?;

    Ok(spki_der.as_bytes().to_vec())
}

/// Extract public key SPKI from PKCS1 private key
///
/// Convenience function that derives public key from private then converts to SPKI.
///
/// # Arguments
/// * `private_pkcs1_der` - Private key in PKCS1 DER format
///
/// # Returns
/// Public key in SPKI DER format
pub fn private_pkcs1_to_public_spki(private_pkcs1_der: &[u8]) -> VaultResult<Vec<u8>> {
    // Parse private key
    let private_key = RsaPrivateKey::from_pkcs1_der(private_pkcs1_der).map_err(|e| {
        VaultError::Crypto(format!("Failed to parse PKCS1 private key: {}", e))
    })?;

    // Derive public key
    let public_key = RsaPublicKey::from(&private_key);

    // Encode to SPKI
    let spki_der = public_key.to_public_key_der().map_err(|e| {
        VaultError::Crypto(format!("Failed to encode SPKI public key: {}", e))
    })?;

    Ok(spki_der.as_bytes().to_vec())
}
