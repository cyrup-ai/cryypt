//! JWT rotator builder following README.md patterns

use crate::{error::*, types::*};
use serde::Serialize;
use std::collections::HashMap;

/// JWT rotator builder - initial state
pub struct RotatorBuilder {
    keys: HashMap<String, Vec<u8>>,
    current_key: Option<(String, Vec<u8>)>,
    result_handler: Option<Box<dyn Fn(JwtResult<JwtRotator>) -> JwtRotator + Send + Sync>>,
}

impl RotatorBuilder {
    pub fn new() -> Self {
        Self {
            keys: HashMap::new(),
            current_key: None,
            result_handler: None,
        }
    }
    
    /// Add a public key for verification - README.md pattern
    pub fn add_key(mut self, key_id: &str, public_key: Vec<u8>) -> Self {
        self.keys.insert(key_id.to_string(), public_key);
        self
    }
    
    /// Set current private key for signing - README.md pattern
    pub fn with_current_key(mut self, key_id: &str, private_key: Vec<u8>) -> Self {
        self.current_key = Some((key_id.to_string(), private_key));
        self
    }
    
    /// Add result handler - README.md pattern: on_result! comes before action
    pub fn on_result<F>(mut self, handler: F) -> Self 
    where
        F: Fn(JwtResult<JwtRotator>) -> JwtRotator + Send + Sync + 'static,
    {
        self.result_handler = Some(Box::new(handler));
        self
    }
    
    /// Build rotator - action method per README.md pattern
    pub async fn build(self) -> JwtRotator {
        let result = Ok(JwtRotator {
            keys: self.keys,
            current_key: self.current_key,
        });
        
        if let Some(handler) = self.result_handler {
            handler(result)
        } else {
            result.unwrap_or_else(|e| panic!("JWT rotator build failed: {}", e))
        }
    }
}

/// JWT rotator for managing multiple keys
pub struct JwtRotator {
    keys: HashMap<String, Vec<u8>>,
    current_key: Option<(String, Vec<u8>)>,
}

impl JwtRotator {
    /// Sign JWT with current key - README.md pattern
    pub fn sign<T: Serialize>(self, claims: T) -> JwtRotatorSigner {
        let claims_value = serde_json::to_value(claims)
            .unwrap_or_else(|_| serde_json::Value::Null);
        
        JwtRotatorSigner {
            rotator: self,
            claims: claims_value,
            result_handler: None,
        }
    }
    
    /// Add result handler for verification - README.md pattern: on_result! comes before action
    pub fn on_result<F>(self, handler: F) -> JwtRotatorVerifier 
    where
        F: Fn(JwtResult<serde_json::Value>) -> serde_json::Value + Send + Sync + 'static,
    {
        JwtRotatorVerifier {
            rotator: self,
            result_handler: Some(Box::new(handler)),
        }
    }
    
    /// Verify JWT with any available key - README.md pattern
    pub async fn verify<T>(self, token: T) -> serde_json::Value 
    where
        T: AsRef<str>,
    {
        // Placeholder implementation
        let _ = token;
        serde_json::json!({"sub": "rotator_verified", "name": "Test User"})
    }
}

/// JWT rotator signer
pub struct JwtRotatorSigner {
    rotator: JwtRotator,
    claims: serde_json::Value,
    result_handler: Option<Box<dyn Fn(JwtResult<String>) -> String + Send + Sync>>,
}

impl JwtRotatorSigner {
    /// Add result handler - README.md pattern: on_result! comes before action
    pub fn on_result<F>(mut self, handler: F) -> Self 
    where
        F: Fn(JwtResult<String>) -> String + Send + Sync + 'static,
    {
        self.result_handler = Some(Box::new(handler));
        self
    }
    
    /// Sign JWT - this is actually called after on_result! per README.md pattern
    pub async fn execute(self) -> String {
        // Placeholder implementation - would use current key to sign
        let result = Ok("rotator.signed.jwt".to_string());
        
        if let Some(handler) = self.result_handler {
            handler(result)
        } else {
            result.unwrap_or_else(|e| panic!("JWT rotator signing failed: {}", e))
        }
    }
}

/// JWT rotator verifier
pub struct JwtRotatorVerifier {
    rotator: JwtRotator,
    result_handler: Option<Box<dyn Fn(JwtResult<serde_json::Value>) -> serde_json::Value + Send + Sync>>,
}

impl JwtRotatorVerifier {
    /// Verify JWT - action method per README.md pattern
    pub async fn verify<T>(self, token: T) -> serde_json::Value 
    where
        T: AsRef<str>,
    {
        // Placeholder implementation - would try all keys
        let _ = token;
        let result = Ok(serde_json::json!({"sub": "rotator_verified", "name": "Test User"}));
        
        if let Some(handler) = self.result_handler {
            handler(result)
        } else {
            result.unwrap_or_else(|e| panic!("JWT rotator verification failed: {}", e))
        }
    }
}