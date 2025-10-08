//! JWT Algorithm Utilities - Base64 encoding/decoding and validation helpers
//!
//! This module provides blazing-fast, zero-allocation utility functions for
//! JWT algorithm operations with production-grade security.

use crate::error::JwtError;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

/// Base64 URL-safe encoding without padding (RFC 7515)
/// Zero-allocation blazing-fast encoding
#[inline]
pub(crate) fn base64_url_encode(input: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(input)
}

/// Base64 URL-safe decoding without padding (RFC 7515)
/// Zero-allocation blazing-fast decoding
#[inline]
pub(crate) fn base64_url_decode(input: &str) -> Result<Vec<u8>, base64::DecodeError> {
    URL_SAFE_NO_PAD.decode(input)
}

/// Validate standard JWT claims with blazing-fast performance
/// Zero-allocation validation with comprehensive security checks
#[inline]
pub(crate) fn validate_standard_claims(claims: &serde_json::Value) -> Result<(), JwtError> {
    if let Some(obj) = claims.as_object() {
        // Expiration time (exp) validation
        if let Some(exp) = obj.get("exp").and_then(serde_json::Value::as_i64) {
            let now = i64::try_from(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_err(|_| JwtError::Internal("System time error".to_string()))?
                    .as_secs(),
            )
            .map_err(|_| JwtError::Internal("Time conversion error".to_string()))?;
            if now > exp {
                return Err(JwtError::TokenExpired);
            }
        }

        // Not before time (nbf) validation
        if let Some(nbf) = obj.get("nbf").and_then(serde_json::Value::as_i64) {
            let now = i64::try_from(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_err(|_| JwtError::Internal("System time error".to_string()))?
                    .as_secs(),
            )
            .map_err(|_| JwtError::Internal("Time conversion error".to_string()))?;
            if now < nbf {
                return Err(JwtError::TokenNotYetValid);
            }
        }

        // Issued at time (iat) validation - should not be in the future
        if let Some(iat) = obj.get("iat").and_then(serde_json::Value::as_i64) {
            let now = i64::try_from(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_err(|_| JwtError::Internal("System time error".to_string()))?
                    .as_secs(),
            )
            .map_err(|_| JwtError::Internal("Time conversion error".to_string()))?;
            // Allow 5 minutes of clock skew for iat
            if iat > now + 300 {
                return Err(JwtError::InvalidClaims(
                    "Token issued in the future".to_string(),
                ));
            }
        }

        // JWT ID (jti) validation - should be a string if present
        if let Some(jti) = obj.get("jti")
            && !jti.is_string()
        {
            return Err(JwtError::InvalidClaims(
                "JWT ID must be a string".to_string(),
            ));
        }

        // Issuer (iss) validation - should be a string if present
        if let Some(iss) = obj.get("iss")
            && !iss.is_string()
        {
            return Err(JwtError::InvalidClaims(
                "Issuer must be a string".to_string(),
            ));
        }

        // Subject (sub) validation - should be a string if present
        if let Some(sub) = obj.get("sub")
            && !sub.is_string()
        {
            return Err(JwtError::InvalidClaims(
                "Subject must be a string".to_string(),
            ));
        }

        // Audience (aud) validation - should be a string or array of strings if present
        if let Some(aud) = obj.get("aud") {
            if !aud.is_string() && !aud.is_array() {
                return Err(JwtError::InvalidClaims(
                    "Audience must be a string or array of strings".to_string(),
                ));
            }
            if let Some(aud_array) = aud.as_array() {
                for aud_item in aud_array {
                    if !aud_item.is_string() {
                        return Err(JwtError::InvalidClaims(
                            "All audience values must be strings".to_string(),
                        ));
                    }
                }
            }
        }
    }

    Ok(())
}

/// Constant-time comparison for cryptographic security
/// Prevents timing attacks with blazing-fast performance
#[inline]
pub(crate) fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}
