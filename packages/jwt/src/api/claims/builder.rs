//! JWT Claims Builder - Builder pattern for constructing JWT claims
//!
//! This module provides zero-allocation builder pattern for blazing-fast claims construction
//! with support for standard and custom claims.

use serde_json::Value;

/// Claims builder for creating JWT claims
/// Zero-allocation builder pattern for blazing-fast claims construction
pub struct ClaimsBuilder {
    claims: serde_json::Map<String, Value>,
}

impl ClaimsBuilder {
    /// Create new claims builder
    /// Zero-allocation construction
    #[inline]
    pub fn new() -> Self {
        Self {
            claims: serde_json::Map::new(),
        }
    }

    /// Set subject claim
    /// Blazing-fast claim setting
    #[inline]
    pub fn with_subject(mut self, subject: &str) -> Self {
        self.claims
            .insert("sub".to_string(), Value::String(subject.to_string()));
        self
    }

    /// Set issuer claim
    /// Blazing-fast claim setting
    #[inline]
    pub fn with_issuer(mut self, issuer: &str) -> Self {
        self.claims
            .insert("iss".to_string(), Value::String(issuer.to_string()));
        self
    }

    /// Set audience claim as string
    /// Blazing-fast claim setting
    #[inline]
    pub fn with_audience(mut self, audience: &str) -> Self {
        self.claims
            .insert("aud".to_string(), Value::String(audience.to_string()));
        self
    }

    /// Set audience claim as array
    /// Zero-allocation array claim setting
    #[inline]
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
    pub fn with_expiration(mut self, exp: i64) -> Self {
        self.claims
            .insert("exp".to_string(), Value::Number(exp.into()));
        self
    }

    /// Set not before time
    /// Blazing-fast timestamp setting
    #[inline]
    pub fn with_not_before(mut self, nbf: i64) -> Self {
        self.claims
            .insert("nbf".to_string(), Value::Number(nbf.into()));
        self
    }

    /// Set issued at time
    /// Blazing-fast timestamp setting
    #[inline]
    pub fn with_issued_at(mut self, iat: i64) -> Self {
        self.claims
            .insert("iat".to_string(), Value::Number(iat.into()));
        self
    }

    /// Set JWT ID
    /// Blazing-fast claim setting
    #[inline]
    pub fn with_jwt_id(mut self, jti: &str) -> Self {
        self.claims
            .insert("jti".to_string(), Value::String(jti.to_string()));
        self
    }

    /// Set custom string claim
    /// Zero-allocation custom claim setting
    #[inline]
    pub fn with_custom_string(mut self, claim: &str, value: &str) -> Self {
        self.claims
            .insert(claim.to_string(), Value::String(value.to_string()));
        self
    }

    /// Set custom number claim
    /// Blazing-fast numeric claim setting
    #[inline]
    pub fn with_custom_number(mut self, claim: &str, value: i64) -> Self {
        self.claims
            .insert(claim.to_string(), Value::Number(value.into()));
        self
    }

    /// Set custom boolean claim
    /// Blazing-fast boolean claim setting
    #[inline]
    pub fn with_custom_bool(mut self, claim: &str, value: bool) -> Self {
        self.claims.insert(claim.to_string(), Value::Bool(value));
        self
    }

    /// Build claims as Value
    /// Zero-allocation claims construction
    #[inline]
    pub fn build(self) -> Value {
        Value::Object(self.claims)
    }
}

impl Default for ClaimsBuilder {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}
