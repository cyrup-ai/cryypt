//! ES256 JWT builder following README.md patterns

use crate::{error::*, types::*, crypto};
use serde::Serialize;

/// ES256 JWT builder - initial state
pub struct Es256Builder;

impl Es256Builder {
    pub fn new() -> Self {
        Self
    }
    
    /// Generate key pair - README.md pattern
    pub fn on_result<F>(self, handler: F) -> Es256KeyGenerator 
    where
        F: Fn(JwtResult<Es256KeyPair>) -> Es256KeyPair + Send + Sync + 'static,
    {
        Es256KeyGenerator {
            result_handler: Some(Box::new(handler)),
        }
    }
    
    /// Set private key for signing - README.md pattern
    pub fn with_private_key(self, private_key: &[u8]) -> Es256WithPrivateKey {
        Es256WithPrivateKey {
            private_key: private_key.to_vec(),
            result_handler: None,
        }
    }
    
    /// Set public key for verification - README.md pattern
    pub fn with_public_key(self, public_key: &[u8]) -> Es256WithPublicKey {
        Es256WithPublicKey {
            public_key: public_key.to_vec(),
            result_handler: None,
        }
    }
}

/// ES256 key generator
pub struct Es256KeyGenerator {
    result_handler: Option<Box<dyn Fn(JwtResult<Es256KeyPair>) -> Es256KeyPair + Send + Sync>>,
}

impl Es256KeyGenerator {
    /// Generate keys - action method per README.md pattern
    pub async fn generate_keys(self) -> Es256KeyPair {
        let result = crypto::es256_generate_keys().await;
        
        if let Some(handler) = self.result_handler {
            handler(result)
        } else {
            result.unwrap_or_else(|e| panic!("ES256 key generation failed: {}", e))
        }
    }
}

/// ES256 builder with private key configured
pub struct Es256WithPrivateKey {
    private_key: Vec<u8>,
    result_handler: Option<Box<dyn Fn(JwtResult<String>) -> String + Send + Sync>>,
}

impl Es256WithPrivateKey {
    /// Add result handler - README.md pattern: on_result! comes before action
    pub fn on_result<F>(mut self, handler: F) -> Self 
    where
        F: Fn(JwtResult<String>) -> String + Send + Sync + 'static,
    {
        self.result_handler = Some(Box::new(handler));
        self
    }
    
    /// Set claims for JWT - README.md pattern
    pub fn with_claims<T: Serialize>(self, claims: T) -> Es256WithClaims {
        let claims_value = serde_json::to_value(claims)
            .unwrap_or_else(|_| serde_json::Value::Null);
        
        Es256WithClaims {
            private_key: self.private_key,
            claims: claims_value,
            result_handler: self.result_handler,
        }
    }
}

/// ES256 builder with claims configured
pub struct Es256WithClaims {
    private_key: Vec<u8>,
    claims: serde_json::Value,
    result_handler: Option<Box<dyn Fn(JwtResult<String>) -> String + Send + Sync>>,
}

impl Es256WithClaims {
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
        let header = JwtHeader::new("ES256");
        let result = crypto::es256_sign(&self.private_key, &header, &self.claims).await;
        
        if let Some(handler) = self.result_handler {
            handler(result)
        } else {
            result.unwrap_or_else(|e| panic!("ES256 JWT signing failed: {}", e))
        }
    }
}

/// ES256 builder with public key configured
pub struct Es256WithPublicKey {
    public_key: Vec<u8>,
    result_handler: Option<Box<dyn Fn(JwtResult<serde_json::Value>) -> serde_json::Value + Send + Sync>>,
}

impl Es256WithPublicKey {
    /// Add result handler - README.md pattern: on_result! comes before action
    pub fn on_result<F>(mut self, handler: F) -> Self 
    where
        F: Fn(JwtResult<serde_json::Value>) -> serde_json::Value + Send + Sync + 'static,
    {
        self.result_handler = Some(Box::new(handler));
        self
    }
    
    /// Verify JWT - action method per README.md pattern
    pub async fn verify<T>(self, token: T) -> serde_json::Value 
    where
        T: AsRef<str>,
    {
        let result = crypto::es256_verify(&self.public_key, token.as_ref()).await;
        
        if let Some(handler) = self.result_handler {
            handler(result)
        } else {
            result.unwrap_or_else(|e| panic!("ES256 JWT verification failed: {}", e))
        }
    }
}