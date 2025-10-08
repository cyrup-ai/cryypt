//! JWT key management utilities
//!
//! Contains utilities for key validation, conversion, and management for JWT operations.

use crate::error::JwtError;

/// Validate HMAC secret key length for security
pub(crate) fn validate_hmac_key(secret: &[u8], algorithm: &str) -> Result<(), JwtError> {
    let min_length = match algorithm {
        "HS256" => 32, // 256 bits minimum
        "HS384" => 48, // 384 bits minimum
        "HS512" => 64, // 512 bits minimum
        _ => return Err(JwtError::unsupported_algorithm(algorithm)),
    };

    if secret.len() < min_length {
        return Err(JwtError::invalid_key(&format!(
            "HMAC key for {} must be at least {} bytes, got {}",
            algorithm,
            min_length,
            secret.len()
        )));
    }

    Ok(())
}

/// Validate RSA key format and extract key information
pub(crate) fn validate_rsa_private_key(key_der: &[u8]) -> Result<(), JwtError> {
    use rsa::{RsaPrivateKey, pkcs8::DecodePrivateKey};

    let _key = RsaPrivateKey::from_pkcs8_der(key_der)
        .map_err(|e| JwtError::invalid_key(&format!("Invalid RSA private key: {e}")))?;

    Ok(())
}

/// Validate RSA public key format
pub(crate) fn validate_rsa_public_key(key_der: &[u8]) -> Result<(), JwtError> {
    use rsa::{RsaPublicKey, pkcs8::DecodePublicKey};

    let _key = RsaPublicKey::from_public_key_der(key_der)
        .map_err(|e| JwtError::invalid_key(&format!("Invalid RSA public key: {e}")))?;

    Ok(())
}

/// Validate ECDSA private key format
pub(crate) fn validate_ec_private_key(key_der: &[u8], algorithm: &str) -> Result<(), JwtError> {
    match algorithm {
        "ES256" => {
            use p256::{ecdsa::SigningKey, pkcs8::DecodePrivateKey};
            let _key = SigningKey::from_pkcs8_der(key_der).map_err(|e| {
                JwtError::invalid_key(&format!("Invalid EC private key for ES256: {e}"))
            })?;
        }
        "ES384" => {
            use p384::{ecdsa::SigningKey, pkcs8::DecodePrivateKey};
            let _key = SigningKey::from_pkcs8_der(key_der).map_err(|e| {
                JwtError::invalid_key(&format!("Invalid EC private key for ES384: {e}"))
            })?;
        }
        _ => return Err(JwtError::unsupported_algorithm(algorithm)),
    }

    Ok(())
}

/// Validate ECDSA public key format
pub(crate) fn validate_ec_public_key(key_der: &[u8], algorithm: &str) -> Result<(), JwtError> {
    match algorithm {
        "ES256" => {
            use p256::{ecdsa::VerifyingKey, pkcs8::DecodePublicKey};
            let _key = VerifyingKey::from_public_key_der(key_der).map_err(|e| {
                JwtError::invalid_key(&format!("Invalid EC public key for ES256: {e}"))
            })?;
        }
        "ES384" => {
            use p384::{ecdsa::VerifyingKey, pkcs8::DecodePublicKey};
            let _key = VerifyingKey::from_public_key_der(key_der).map_err(|e| {
                JwtError::invalid_key(&format!("Invalid EC public key for ES384: {e}"))
            })?;
        }
        _ => return Err(JwtError::unsupported_algorithm(algorithm)),
    }

    Ok(())
}

/// Get recommended key size for algorithm
///
/// # Errors
/// Returns `JwtError` if the algorithm is not supported
pub fn get_recommended_key_size(algorithm: &str) -> Result<usize, JwtError> {
    match algorithm {
        "HS256" | "ES256" => Ok(32),            // 256 bits / P-256 curve
        "HS384" | "ES384" => Ok(48),            // 384 bits / P-384 curve
        "HS512" => Ok(64),                      // 512 bits
        "RS256" | "RS384" | "RS512" => Ok(256), // 2048 bits RSA minimum
        _ => Err(JwtError::unsupported_algorithm(algorithm)),
    }
}
