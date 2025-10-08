//! HS256 JWT builder following README.md patterns

use crate::{error::*, types::*, crypto};
use cryypt_common::error::LoggingTransformer;
use serde::Serialize;
use std::time::Duration;

/// HS256 JWT builder - initial state
pub struct Hs256Builder;

impl Hs256Builder {
    pub fn new() -> Self {
        Self
    }
    
    /// Set secret for HMAC-SHA256 - README.md pattern
    pub fn with_secret(self, secret: &[u8]) -> Hs256WithSecret {
        Hs256WithSecret {
            secret: secret.to_vec(),
            result_handler: None,
        }
    }
}

/// HS256 builder with secret configured
pub struct Hs256WithSecret {
    secret: Vec<u8>,
    result_handler: Option<Box<dyn Fn(JwtResult<String>) -> String + Send + Sync>>,
}

impl Hs256WithSecret {
    /// Add result handler - README.md pattern: on_result! comes before action
    pub fn on_result<F>(mut self, handler: F) -> Self 
    where
        F: Fn(JwtResult<String>) -> String + Send + Sync + 'static,
    {
        self.result_handler = Some(Box::new(handler));
        self
    }
    
    /// Set claims for JWT - README.md pattern
    pub fn with_claims<T: Serialize>(self, claims: T) -> Result<Hs256WithClaims, JwtError> {
        let claims_value = serde_json::to_value(claims)
            .map_err(|e| JwtError::serialization(&format!("Failed to serialize claims: {e}")))?;
        
        Ok(Hs256WithClaims {
            secret: self.secret,
            claims: claims_value,
            expiry: None,
            result_handler: self.result_handler,
        })
    }
}

/// HS256 builder with claims configured
pub struct Hs256WithClaims {
    secret: Vec<u8>,
    claims: serde_json::Value,
    expiry: Option<Duration>,
    result_handler: Option<Box<dyn Fn(JwtResult<String>) -> String + Send + Sync>>,
}

impl Hs256WithClaims {
    /// Set expiry duration - README.md pattern
    pub fn with_expiry(mut self, duration: Duration) -> Self {
        self.expiry = Some(duration);
        self
    }
    
    /// Add result handler - README.md pattern: on_result! comes before action
    pub fn on_result<F>(mut self, handler: F) -> Self 
    where
        F: Fn(JwtResult<String>) -> String + Send + Sync + 'static,
    {
        self.result_handler = Some(Box::new(handler));
        self
    }
    
    /// Sign JWT - action method per README.md pattern
    pub async fn sign(self) -> Result<String, JwtError> {
        let header = JwtHeader::new("HS256");
        
        // Add expiry to claims if specified
        let mut claims = self.claims;
        if let Some(expiry) = self.expiry {
            let exp = chrono::Utc::now().timestamp() + i64::try_from(expiry.as_secs()).map_err(|_| crate::error::JwtError::Internal("Expiry time conversion error".to_string()))?;
            if let serde_json::Value::Object(ref mut map) = claims {
                map.insert("exp".to_string(), serde_json::Value::Number(serde_json::Number::from(exp)));
            }
        }
        
        let result = crypto::hs256_sign(&self.secret, &header, &claims).await;
        
        if let Some(handler) = self.result_handler {
            Ok(handler(result))
        } else {
            match result {
                Ok(jwt) => Ok(jwt),
                Err(e) => {
                    LoggingTransformer::log_jwt_error("jwt_signing", "HS256", &e.to_string());
                    Err(e)
                }
            }
        }
    }
}

/// HS256 verification builder
pub struct Hs256Verifier {
    secret: Vec<u8>,
    result_handler: Option<Box<dyn Fn(JwtResult<serde_json::Value>) -> serde_json::Value + Send + Sync>>,
}

impl Hs256WithSecret {
    /// Add result handler for verification - README.md pattern: on_result! comes before action
    pub fn on_result_verify<F>(self, handler: F) -> Hs256Verifier 
    where
        F: Fn(JwtResult<serde_json::Value>) -> serde_json::Value + Send + Sync + 'static,
    {
        Hs256Verifier {
            secret: self.secret,
            result_handler: Some(Box::new(handler)),
        }
    }
}

impl Hs256Verifier {
    /// Verify JWT - action method per README.md pattern
    pub async fn verify<T>(self, token: T) -> Result<serde_json::Value, JwtError>
    where
        T: AsRef<str>,
    {
        let result = crypto::hs256_verify(&self.secret, token.as_ref()).await;
        
        if let Some(handler) = self.result_handler {
            Ok(handler(result))
        } else {
            match result {
                Ok(claims) => Ok(claims),
                Err(e) => {
                    LoggingTransformer::log_jwt_error("jwt_verification", "HS256", &e.to_string());
                    Err(e)
                }
            }
        }
    }
}

