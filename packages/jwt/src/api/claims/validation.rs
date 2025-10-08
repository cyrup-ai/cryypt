//! JWT Standard Claims Validation - Core validation logic for standard JWT claims
//!
//! This module provides blazing-fast, zero-allocation JWT claims validation
//! with comprehensive security checks for standard claims.

use crate::error::JwtError;
use serde_json::Value;

/// Get current Unix timestamp with error handling
#[inline]
fn get_current_timestamp() -> Result<i64, JwtError> {
    i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| JwtError::Internal("System time error".to_string()))?
            .as_secs(),
    )
    .map_err(|_| JwtError::Internal("Time conversion error".to_string()))
}

/// Validate time-based claims (exp, nbf, iat)
#[inline]
fn validate_time_claims(obj: &serde_json::Map<String, Value>) -> Result<(), JwtError> {
    let now = get_current_timestamp()?;

    // Check expiration
    if let Some(exp) = obj.get("exp").and_then(Value::as_i64)
        && now > exp
    {
        return Err(JwtError::TokenExpired);
    }

    // Check not before
    if let Some(nbf) = obj.get("nbf").and_then(Value::as_i64)
        && now < nbf
    {
        return Err(JwtError::TokenNotYetValid);
    }

    // Validate exp > nbf if both present
    if let (Some(exp), Some(nbf)) = (
        obj.get("exp").and_then(Value::as_i64),
        obj.get("nbf").and_then(Value::as_i64),
    ) && exp <= nbf
    {
        return Err(JwtError::InvalidClaims("exp must be after nbf".to_string()));
    }

    // Validate issued at time (allow 5 minutes clock skew)
    if let Some(iat) = obj.get("iat").and_then(Value::as_i64)
        && iat > now + 300
    {
        return Err(JwtError::InvalidClaims("iat is in the future".to_string()));
    }

    Ok(())
}

/// Validate string claim (must be non-empty string if present)
#[inline]
fn validate_string_claim(
    obj: &serde_json::Map<String, Value>,
    claim_name: &str,
) -> Result<(), JwtError> {
    if let Some(value) = obj.get(claim_name) {
        if let Some(str_value) = value.as_str() {
            if str_value.is_empty() {
                return Err(JwtError::InvalidClaims(format!(
                    "{claim_name} cannot be empty"
                )));
            }
        } else {
            return Err(JwtError::InvalidClaims(format!(
                "{claim_name} must be a string"
            )));
        }
    }
    Ok(())
}

/// Validate audience claim (string or array of strings)
#[inline]
fn validate_audience_claim(obj: &serde_json::Map<String, Value>) -> Result<(), JwtError> {
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
    Ok(())
}

/// Validate standard JWT claims with blazing-fast performance
/// Zero-allocation validation with comprehensive security checks
#[inline]
pub(crate) fn validate_standard_claims(claims: &serde_json::Value) -> Result<(), JwtError> {
    if let Some(obj) = claims.as_object() {
        validate_time_claims(obj)?;
        validate_string_claim(obj, "jti")?;
        validate_string_claim(obj, "iss")?;
        validate_string_claim(obj, "sub")?;
        validate_audience_claim(obj)?;
    }
    Ok(())
}
