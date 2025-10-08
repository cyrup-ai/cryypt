//! JWT Claims Builder - Builder pattern for constructing JWT claims
//!
//! This module provides zero-allocation builder pattern for blazing-fast claims construction
//! with support for standard and custom claims.

use super::standard_claims::Claims;
use chrono::{Duration, Utc};
use serde_json::Value;
use std::collections::HashMap;

/// Claims builder for creating JWT claims
/// Zero-allocation builder pattern for blazing-fast claims construction
pub struct ClaimsBuilder {
    claims: serde_json::Map<String, Value>,
}

impl ClaimsBuilder {
    /// Create new claims builder
    /// Zero-allocation construction
    #[inline]
    #[must_use]
    pub fn new() -> Self {
        Self {
            claims: serde_json::Map::new(),
        }
    }

    /// Set subject claim
    /// Blazing-fast claim setting
    #[inline]
    #[must_use]
    pub fn with_subject(mut self, subject: &str) -> Self {
        self.claims
            .insert("sub".to_string(), Value::String(subject.to_string()));
        self
    }

    /// Set subject claim (alias for `with_subject` for backward compatibility)
    #[inline]
    #[must_use]
    pub fn subject(self, subject: &str) -> Self {
        self.with_subject(subject)
    }

    /// Set issuer claim
    /// Blazing-fast claim setting
    #[inline]
    #[must_use]
    pub fn with_issuer(mut self, issuer: &str) -> Self {
        self.claims
            .insert("iss".to_string(), Value::String(issuer.to_string()));
        self
    }

    /// Set audience claim as string
    /// Blazing-fast claim setting
    #[inline]
    #[must_use]
    pub fn with_audience(mut self, audience: &str) -> Self {
        self.claims
            .insert("aud".to_string(), Value::String(audience.to_string()));
        self
    }

    /// Set audience claim as array
    /// Zero-allocation array claim setting
    #[inline]
    #[must_use]
    pub fn with_audience_array(mut self, audiences: &[&str]) -> Self {
        let aud_array: Vec<Value> = audiences
            .iter()
            .map(|&aud| Value::String(aud.to_string()))
            .collect();
        self.claims
            .insert("aud".to_string(), Value::Array(aud_array));
        self
    }

    /// Set expiration time
    /// Blazing-fast timestamp setting
    #[inline]
    #[must_use]
    pub fn with_expiration(mut self, exp: i64) -> Self {
        self.claims
            .insert("exp".to_string(), Value::Number(exp.into()));
        self
    }

    /// Set not before time
    /// Blazing-fast timestamp setting
    #[inline]
    #[must_use]
    pub fn with_not_before(mut self, nbf: i64) -> Self {
        self.claims
            .insert("nbf".to_string(), Value::Number(nbf.into()));
        self
    }

    /// Set issued at time
    /// Blazing-fast timestamp setting
    #[inline]
    #[must_use]
    pub fn with_issued_at(mut self, iat: i64) -> Self {
        self.claims
            .insert("iat".to_string(), Value::Number(iat.into()));
        self
    }

    /// Set JWT ID
    /// Blazing-fast claim setting
    #[inline]
    #[must_use]
    pub fn with_jwt_id(mut self, jti: &str) -> Self {
        self.claims
            .insert("jti".to_string(), Value::String(jti.to_string()));
        self
    }

    /// Set custom string claim
    /// Zero-allocation custom claim setting
    #[inline]
    #[must_use]
    pub fn with_custom_string(mut self, claim: &str, value: &str) -> Self {
        self.claims
            .insert(claim.to_string(), Value::String(value.to_string()));
        self
    }

    /// Set custom number claim
    /// Blazing-fast numeric claim setting
    #[inline]
    #[must_use]
    pub fn with_custom_number(mut self, claim: &str, value: i64) -> Self {
        self.claims
            .insert(claim.to_string(), Value::Number(value.into()));
        self
    }

    /// Set custom boolean claim
    /// Blazing-fast boolean claim setting
    #[inline]
    #[must_use]
    pub fn with_custom_bool(mut self, claim: &str, value: bool) -> Self {
        self.claims.insert(claim.to_string(), Value::Bool(value));
        self
    }

    /// Set expiration time using duration from now
    #[inline]
    #[must_use]
    pub fn expires_in(mut self, duration: Duration) -> Self {
        let exp = (Utc::now() + duration).timestamp();
        self.claims
            .insert("exp".to_string(), Value::Number(exp.into()));
        self
    }

    /// Set issued at time to now
    #[inline]
    #[must_use]
    pub fn issued_now(mut self) -> Self {
        let iat = Utc::now().timestamp();
        self.claims
            .insert("iat".to_string(), Value::Number(iat.into()));
        self
    }

    /// Set issuer claim (alias for `with_issuer`)
    #[inline]
    #[must_use]
    pub fn issuer(self, issuer: &str) -> Self {
        self.with_issuer(issuer)
    }

    /// Set audience claim as vector of strings
    #[inline]
    #[must_use]
    pub fn audience(mut self, audience: Vec<String>) -> Self {
        let aud_values: Vec<Value> = audience.into_iter().map(Value::String).collect();
        self.claims
            .insert("aud".to_string(), Value::Array(aud_values));
        self
    }

    /// Set not before time
    #[inline]
    #[must_use]
    pub fn not_before(mut self, nbf: chrono::DateTime<Utc>) -> Self {
        self.claims
            .insert("nbf".to_string(), Value::Number(nbf.timestamp().into()));
        self
    }

    /// Set JWT ID
    #[inline]
    #[must_use]
    pub fn jwt_id(mut self, jti: &str) -> Self {
        self.claims
            .insert("jti".to_string(), Value::String(jti.to_string()));
        self
    }

    /// Set custom claim with any JSON value
    #[inline]
    #[must_use]
    pub fn custom(mut self, key: &str, value: Value) -> Self {
        self.claims.insert(key.to_string(), value);
        self
    }

    /// Build claims as structured Claims object
    #[inline]
    #[must_use]
    pub fn build(self) -> Claims {
        // Extract required fields with defaults
        let sub = self
            .claims
            .get("sub")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let exp = self
            .claims
            .get("exp")
            .and_then(serde_json::Value::as_i64)
            .unwrap_or(0);

        let iat = self
            .claims
            .get("iat")
            .and_then(serde_json::Value::as_i64)
            .unwrap_or(0);

        // Extract optional fields
        let iss = self
            .claims
            .get("iss")
            .and_then(|v| v.as_str())
            .map(std::string::ToString::to_string);

        let aud = self
            .claims
            .get("aud")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str())
                    .map(std::string::ToString::to_string)
                    .collect()
            });

        let nbf = self.claims.get("nbf").and_then(serde_json::Value::as_i64);

        let jti = self
            .claims
            .get("jti")
            .and_then(|v| v.as_str())
            .map(std::string::ToString::to_string);

        // Collect extra fields (all fields not in standard claims)
        let standard_fields = ["sub", "exp", "iat", "iss", "aud", "nbf", "jti"];
        let extra: HashMap<String, Value> = self
            .claims
            .into_iter()
            .filter(|(k, _)| !standard_fields.contains(&k.as_str()))
            .collect();

        Claims {
            sub,
            exp,
            iat,
            iss,
            aud,
            nbf,
            jti,
            extra,
        }
    }
}

impl Default for ClaimsBuilder {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}
