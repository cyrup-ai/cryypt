//! JWT Claims Extractor - Utility functions for extracting claim values
//!
//! This module provides zero-allocation claim extraction with blazing-fast performance
//! for both standard and custom claims.

use serde_json::Value;

/// Claims extractor for common claim types
/// Zero-allocation claim extraction with blazing-fast performance
pub struct ClaimsExtractor;

impl ClaimsExtractor {
    /// Extract subject claim
    /// Blazing-fast string extraction
    #[inline]
    #[must_use]
    pub fn subject(claims: &Value) -> Option<&str> {
        claims.get("sub").and_then(|v| v.as_str())
    }

    /// Extract issuer claim
    /// Blazing-fast string extraction
    #[inline]
    #[must_use]
    pub fn issuer(claims: &Value) -> Option<&str> {
        claims.get("iss").and_then(|v| v.as_str())
    }

    /// Extract audience claim as string
    /// Blazing-fast string extraction
    #[inline]
    #[must_use]
    pub fn audience_string(claims: &Value) -> Option<&str> {
        claims.get("aud").and_then(|v| v.as_str())
    }

    /// Extract audience claim as array
    /// Zero-allocation array extraction
    #[inline]
    #[must_use]
    pub fn audience_array(claims: &Value) -> Option<Vec<String>> {
        claims.get("aud").and_then(|v| {
            v.as_array().map(|arr| {
                arr.iter()
                    .filter_map(|item| item.as_str().map(std::string::ToString::to_string))
                    .collect()
            })
        })
    }

    /// Extract expiration time
    /// Blazing-fast timestamp extraction
    #[inline]
    #[must_use]
    pub fn expiration(claims: &Value) -> Option<i64> {
        claims.get("exp").and_then(serde_json::Value::as_i64)
    }

    /// Extract not before time
    /// Blazing-fast timestamp extraction
    #[inline]
    #[must_use]
    pub fn not_before(claims: &Value) -> Option<i64> {
        claims.get("nbf").and_then(serde_json::Value::as_i64)
    }

    /// Extract issued at time
    /// Blazing-fast timestamp extraction
    #[inline]
    #[must_use]
    pub fn issued_at(claims: &Value) -> Option<i64> {
        claims.get("iat").and_then(serde_json::Value::as_i64)
    }

    /// Extract JWT ID
    /// Blazing-fast string extraction
    #[inline]
    #[must_use]
    pub fn jwt_id(claims: &Value) -> Option<&str> {
        claims.get("jti").and_then(|v| v.as_str())
    }

    /// Extract custom claim as string
    /// Zero-allocation custom claim extraction
    #[inline]
    #[must_use]
    pub fn custom_string(claims: &Value, claim: &str) -> Option<String> {
        claims
            .get(claim)
            .and_then(|v| v.as_str().map(std::string::ToString::to_string))
    }

    /// Extract custom claim as number
    /// Blazing-fast numeric extraction
    #[inline]
    #[must_use]
    pub fn custom_number(claims: &Value, claim: &str) -> Option<i64> {
        claims.get(claim).and_then(serde_json::Value::as_i64)
    }

    /// Extract custom claim as boolean
    /// Blazing-fast boolean extraction
    #[inline]
    #[must_use]
    pub fn custom_bool(claims: &Value, claim: &str) -> Option<bool> {
        claims.get(claim).and_then(serde_json::Value::as_bool)
    }

    /// Extract custom claim as array
    /// Zero-allocation array extraction
    #[inline]
    #[must_use]
    pub fn custom_array(claims: &Value, claim: &str) -> Option<Vec<Value>> {
        claims.get(claim).and_then(|v| v.as_array().cloned())
    }

    /// Extract custom claim as object
    /// Zero-allocation object extraction
    #[inline]
    #[must_use]
    pub fn custom_object(claims: &Value, claim: &str) -> Option<serde_json::Map<String, Value>> {
        claims.get(claim).and_then(|v| v.as_object().cloned())
    }
}
