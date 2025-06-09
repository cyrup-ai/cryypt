//! JWT validation options and configuration.

use chrono::Duration;

/// JWT validation options.
#[derive(Debug, Clone)]
pub struct ValidationOptions {
    /// Leeway for time-based claims.
    pub leeway: Duration,
    /// Validate expiry.
    pub validate_exp: bool,
    /// Validate not-before.
    pub validate_nbf: bool,
    /// Required claims.
    pub required_claims: Vec<String>,
    /// Allowed algorithms.
    pub allowed_algorithms: Vec<&'static str>,
    /// Expected issuer.
    pub expected_issuer: Option<String>,
    /// Expected audience.
    pub expected_audience: Option<Vec<String>>,
}

impl Default for ValidationOptions {
    fn default() -> Self {
        Self {
            leeway: Duration::seconds(60),
            validate_exp: true,
            validate_nbf: true,
            required_claims: vec![],
            allowed_algorithms: vec!["HS256", "ES256"],
            expected_issuer: None,
            expected_audience: None,
        }
    }
}

impl ValidationOptions {
    /// Create validation options that skip all validation.
    ///
    /// # Safety
    /// This should only be used for testing or when you're certain
    /// about the token's validity.
    pub fn insecure_for_testing() -> Self {
        Self {
            leeway: Duration::seconds(i64::MAX),
            validate_exp: false,
            validate_nbf: false,
            required_claims: vec![],
            allowed_algorithms: vec!["HS256", "ES256", "RS256", "PS256"],
            expected_issuer: None,
            expected_audience: None,
        }
    }

    /// Create strict validation options with no leeway.
    pub fn strict() -> Self {
        Self {
            leeway: Duration::zero(),
            validate_exp: true,
            validate_nbf: true,
            required_claims: vec![],
            allowed_algorithms: vec!["ES256"], // Only allow ES256 by default
            expected_issuer: None,
            expected_audience: None,
        }
    }

    /// Set the time leeway for validation.
    pub fn with_leeway(mut self, leeway: Duration) -> Self {
        self.leeway = leeway;
        self
    }

    /// Set whether to validate expiration.
    pub fn validate_expiration(mut self, validate: bool) -> Self {
        self.validate_exp = validate;
        self
    }

    /// Set whether to validate not-before.
    pub fn validate_not_before(mut self, validate: bool) -> Self {
        self.validate_nbf = validate;
        self
    }

    /// Add a required claim.
    pub fn require_claim(mut self, claim: impl Into<String>) -> Self {
        self.required_claims.push(claim.into());
        self
    }

    /// Set allowed algorithms.
    pub fn allowed_algorithms(mut self, algorithms: Vec<&'static str>) -> Self {
        self.allowed_algorithms = algorithms;
        self
    }

    /// Set expected issuer.
    pub fn expect_issuer(mut self, issuer: impl Into<String>) -> Self {
        self.expected_issuer = Some(issuer.into());
        self
    }

    /// Set expected audience.
    pub fn expect_audience(mut self, audience: Vec<String>) -> Self {
        self.expected_audience = Some(audience);
        self
    }
}
