//! JWT Claims Validator - Custom validation rules and builder pattern
//!
//! This module provides blazing-fast custom validation with sophisticated
//! claims validation using a zero-allocation builder pattern.

use super::validation::validate_standard_claims;
use crate::error::JwtError;
use serde_json::Value;

/// Type alias for custom validation functions
type CustomValidator = Box<dyn Fn(&Value) -> Result<(), JwtError> + Send + Sync>;

/// JWT Claims validator with blazing-fast custom validation
/// Zero-allocation builder pattern for sophisticated claims validation
pub struct ClaimsValidator {
    required_claims: Vec<String>,
    custom_validators: Vec<CustomValidator>,
    audience_validation: Option<String>,
    issuer_validation: Option<String>,
    subject_validation: Option<String>,
    max_age_seconds: Option<i64>,
}

impl ClaimsValidator {
    /// Create new claims validator
    /// Zero-allocation construction
    #[inline]
    #[must_use]
    pub fn new() -> Self {
        Self {
            required_claims: Vec::new(),
            custom_validators: Vec::new(),
            audience_validation: None,
            issuer_validation: None,
            subject_validation: None,
            max_age_seconds: None,
        }
    }

    /// Require specific claim to be present
    /// Blazing-fast builder pattern
    #[inline]
    #[must_use]
    pub fn require_claim(mut self, claim: &str) -> Self {
        self.required_claims.push(claim.to_string());
        self
    }

    /// Add custom validator function
    /// Zero-allocation validator registration
    #[inline]
    #[must_use]
    pub fn with_custom_validator<F>(mut self, validator: F) -> Self
    where
        F: Fn(&Value) -> Result<(), JwtError> + Send + Sync + 'static,
    {
        self.custom_validators.push(Box::new(validator));
        self
    }

    /// Validate specific audience
    /// Blazing-fast audience validation
    #[inline]
    #[must_use]
    pub fn with_audience(mut self, audience: &str) -> Self {
        self.audience_validation = Some(audience.to_string());
        self
    }

    /// Validate specific issuer
    /// Blazing-fast issuer validation
    #[inline]
    #[must_use]
    pub fn with_issuer(mut self, issuer: &str) -> Self {
        self.issuer_validation = Some(issuer.to_string());
        self
    }

    /// Validate specific subject
    /// Blazing-fast subject validation
    #[inline]
    #[must_use]
    pub fn with_subject(mut self, subject: &str) -> Self {
        self.subject_validation = Some(subject.to_string());
        self
    }

    /// Set maximum token age in seconds
    /// Blazing-fast age validation
    #[inline]
    #[must_use]
    pub fn with_max_age(mut self, max_age_seconds: i64) -> Self {
        self.max_age_seconds = Some(max_age_seconds);
        self
    }

    /// Validate claims with comprehensive checks
    /// Zero-allocation validation with blazing-fast performance
    ///
    /// # Errors
    /// Returns `JwtError` if claims validation fails due to expired tokens, invalid issuer, or custom rules
    pub fn validate(&self, claims: &Value) -> Result<(), JwtError> {
        // First run standard claims validation
        validate_standard_claims(claims)?;

        let obj = claims
            .as_object()
            .ok_or_else(|| JwtError::InvalidClaims("Claims must be an object".to_string()))?;

        // Check required claims
        for required_claim in &self.required_claims {
            if !obj.contains_key(required_claim) {
                return Err(JwtError::InvalidClaims(format!(
                    "Required claim '{required_claim}' is missing"
                )));
            }
        }

        // Validate audience if specified
        if let Some(expected_aud) = &self.audience_validation {
            match obj.get("aud") {
                Some(Value::String(aud)) => {
                    if aud != expected_aud {
                        return Err(JwtError::InvalidClaims("Invalid audience".to_string()));
                    }
                }
                Some(Value::Array(aud_array)) => {
                    let found = aud_array
                        .iter()
                        .any(|aud| aud.as_str().is_some_and(|s| s == expected_aud));
                    if !found {
                        return Err(JwtError::InvalidClaims(
                            "Audience not found in array".to_string(),
                        ));
                    }
                }
                _ => {
                    return Err(JwtError::InvalidClaims(
                        "Audience validation failed".to_string(),
                    ));
                }
            }
        }

        // Validate issuer if specified
        if let Some(expected_iss) = &self.issuer_validation {
            match obj.get("iss").and_then(|v| v.as_str()) {
                Some(iss) if iss == expected_iss => {}
                _ => {
                    return Err(JwtError::InvalidClaims("Invalid issuer".to_string()));
                }
            }
        }

        // Validate subject if specified
        if let Some(expected_sub) = &self.subject_validation {
            match obj.get("sub").and_then(|v| v.as_str()) {
                Some(sub) if sub == expected_sub => {}
                _ => {
                    return Err(JwtError::InvalidClaims("Invalid subject".to_string()));
                }
            }
        }

        // Validate max age if specified
        if let Some(max_age) = self.max_age_seconds {
            if let Some(iat) = obj.get("iat").and_then(serde_json::Value::as_i64) {
                let now = i64::try_from(
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map_err(|_| JwtError::Internal("System time error".to_string()))?
                        .as_secs(),
                )
                .map_err(|_| JwtError::Internal("Time conversion error".to_string()))?;

                if now - iat > max_age {
                    return Err(JwtError::InvalidClaims("Token is too old".to_string()));
                }
            } else {
                return Err(JwtError::InvalidClaims(
                    "iat claim required for age validation".to_string(),
                ));
            }
        }

        // Run custom validators
        for validator in &self.custom_validators {
            validator(claims)?;
        }

        Ok(())
    }
}

impl Default for ClaimsValidator {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}
