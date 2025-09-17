//! JWT Standard Claims Validation - Core validation logic for standard JWT claims
//!
//! This module provides blazing-fast, zero-allocation JWT claims validation
//! with comprehensive security checks for standard claims.

use crate::error::JwtError;
use serde_json::Value;

/// Validate standard JWT claims with blazing-fast performance
/// Zero-allocation validation with comprehensive security checks
#[inline]
pub(crate) fn validate_standard_claims(claims: &serde_json::Value) -> Result<(), JwtError> {
    if let Some(obj) = claims.as_object() {
        // Check expiration with blazing-fast time handling
        if let Some(exp) = obj.get("exp").and_then(serde_json::Value::as_i64) {
            let now = i64::try_from(std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| JwtError::Internal("System time error".to_string()))?
                .as_secs()).map_err(|_| JwtError::Internal("Time conversion error".to_string()))?;

            if now > exp {
                return Err(JwtError::TokenExpired);
            }
        }

        // Check not before with blazing-fast time handling
        if let Some(nbf) = obj.get("nbf").and_then(serde_json::Value::as_i64) {
            let now = i64::try_from(std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| JwtError::Internal("System time error".to_string()))?
                .as_secs()).map_err(|_| JwtError::Internal("Time conversion error".to_string()))?;

            if now < nbf {
                return Err(JwtError::TokenNotYetValid);
            }
        }

        // Validate exp > nbf if both present with zero-allocation checks
        if let (Some(exp), Some(nbf)) = (
            obj.get("exp").and_then(serde_json::Value::as_i64),
            obj.get("nbf").and_then(serde_json::Value::as_i64),
        ) && exp <= nbf
        {
            return Err(JwtError::InvalidClaims("exp must be after nbf".to_string()));
        }

        // Validate issued at time if present
        if let Some(iat) = obj.get("iat").and_then(serde_json::Value::as_i64) {
            let now = i64::try_from(std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| JwtError::Internal("System time error".to_string()))?
                .as_secs()).map_err(|_| JwtError::Internal("Time conversion error".to_string()))?;

            // Allow some clock skew (5 minutes)
            if iat > now + 300 {
                return Err(JwtError::InvalidClaims("iat is in the future".to_string()));
            }
        }

        // Validate JWT ID if present (must be non-empty string)
        if let Some(jti) = obj.get("jti") {
            if let Some(jti_str) = jti.as_str() {
                if jti_str.is_empty() {
                    return Err(JwtError::InvalidClaims("jti cannot be empty".to_string()));
                }
            } else {
                return Err(JwtError::InvalidClaims("jti must be a string".to_string()));
            }
        }

        // Validate issuer if present (must be non-empty string)
        if let Some(iss) = obj.get("iss") {
            if let Some(iss_str) = iss.as_str() {
                if iss_str.is_empty() {
                    return Err(JwtError::InvalidClaims("iss cannot be empty".to_string()));
                }
            } else {
                return Err(JwtError::InvalidClaims("iss must be a string".to_string()));
            }
        }

        // Validate subject if present (must be non-empty string)
        if let Some(sub) = obj.get("sub") {
            if let Some(sub_str) = sub.as_str() {
                if sub_str.is_empty() {
                    return Err(JwtError::InvalidClaims("sub cannot be empty".to_string()));
                }
            } else {
                return Err(JwtError::InvalidClaims("sub must be a string".to_string()));
            }
        }

        // Validate audience if present
        if let Some(aud) = obj.get("aud") {
            match aud {
                Value::String(aud_str) => {
                    if aud_str.is_empty() {
                        return Err(JwtError::InvalidClaims("aud cannot be empty".to_string()));
                    }
                }
                Value::Array(aud_array) => {
                    if aud_array.is_empty() {
                        return Err(JwtError::InvalidClaims(
                            "aud array cannot be empty".to_string(),
                        ));
                    }
                    for aud_item in aud_array {
                        if let Some(aud_str) = aud_item.as_str() {
                            if aud_str.is_empty() {
                                return Err(JwtError::InvalidClaims(
                                    "aud array item cannot be empty".to_string(),
                                ));
                            }
                        } else {
                            return Err(JwtError::InvalidClaims(
                                "aud array items must be strings".to_string(),
                            ));
                        }
                    }
                }
                _ => {
                    return Err(JwtError::InvalidClaims(
                        "aud must be a string or array of strings".to_string(),
                    ));
                }
            }
        }
    }

    Ok(())
}
