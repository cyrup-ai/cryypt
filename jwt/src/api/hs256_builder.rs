//! HS256 JWT builder following README.md patterns

use crate::{error::*, types::*, crypto};
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
    pub fn with_claims<T: Serialize>(self, claims: T) -> Hs256WithClaims {
        let claims_value = serde_json::to_value(claims)
            .unwrap_or_else(|_| serde_json::Value::Null);
        
        Hs256WithClaims {
            secret: self.secret,
            claims: claims_value,
            expiry: None,
            result_handler: self.result_handler,
        }
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
    pub async fn sign(self) -> String {
        let header = JwtHeader::new("HS256");
        
        // Add expiry to claims if specified
        let mut claims = self.claims;
        if let Some(expiry) = self.expiry {
            let exp = chrono::Utc::now().timestamp() + expiry.as_secs() as i64;
            if let serde_json::Value::Object(ref mut map) = claims {
                map.insert("exp".to_string(), serde_json::Value::Number(serde_json::Number::from(exp)));
            }
        }
        
        let result = crypto::hs256_sign(&self.secret, &header, &claims).await;
        
        if let Some(handler) = self.result_handler {
            handler(result)
        } else {
            result.unwrap_or_else(|e| panic!("JWT signing failed: {}", e))
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
    pub async fn verify<T>(self, token: T) -> serde_json::Value 
    where
        T: AsRef<str>,
    {
        let result = crypto::hs256_verify(&self.secret, token.as_ref()).await;
        
        if let Some(handler) = self.result_handler {
            handler(result)
        } else {
            result.unwrap_or_else(|e| panic!("JWT verification failed: {}", e))
        }
    }
}

// Extend Hs256WithSecret to support direct verification
impl Hs256WithSecret {
    /// Verify JWT directly - README.md pattern
    pub async fn verify<T>(self, token: T) -> serde_json::Value 
    where
        T: AsRef<str>,
    {
        let result = crypto::hs256_verify(&self.secret, token.as_ref()).await;
        
        if let Some(handler) = self.result_handler {
            let handler_typed: Box<dyn Fn(JwtResult<serde_json::Value>) -> serde_json::Value + Send + Sync> = 
                unsafe { std::mem::transmute(handler) };
            handler_typed(result)
        } else {
            result.unwrap_or_else(|e| panic!("JWT verification failed: {}", e))
        }
    }
}