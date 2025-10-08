//! JWT type definitions following README.md patterns

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// JWT claims structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtClaims {
    // Standard claims
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>, // Subject
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<String>, // Audience
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<i64>, // Expiration time
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nbf: Option<i64>, // Not before
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iat: Option<i64>, // Issued at
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>, // Issuer
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>, // JWT ID

    // Custom claims (flattened into root)
    #[serde(flatten)]
    pub custom: HashMap<String, serde_json::Value>,
}

impl JwtClaims {
    #[must_use]
    pub fn new() -> Self {
        Self {
            sub: None,
            aud: None,
            exp: None,
            nbf: None,
            iat: None,
            iss: None,
            jti: None,
            custom: HashMap::new(),
        }
    }
}

impl Default for JwtClaims {
    fn default() -> Self {
        Self::new()
    }
}

/// JWT header structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtHeader {
    pub alg: String,
    pub typ: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
}

impl JwtHeader {
    #[must_use]
    pub fn new(alg: &str) -> Self {
        Self {
            alg: alg.to_string(),
            typ: "JWT".to_string(),
            kid: None,
        }
    }

    #[must_use]
    pub fn with_key_id(mut self, kid: String) -> Self {
        self.kid = Some(kid);
        self
    }
}

/// Key pair for ES256
#[derive(Debug, Clone)]
pub struct Es256KeyPair {
    pub private_key: Vec<u8>,
    pub public_key: Vec<u8>,
}

/// JWT token string wrapper
#[derive(Debug, Clone)]
pub struct JwtToken(pub String);

impl From<String> for JwtToken {
    fn from(token: String) -> Self {
        Self(token)
    }
}

impl AsRef<str> for JwtToken {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for JwtToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
