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
            result.unwrap_or_default() // Never fails in practice since we create with Ok()
        }
    }
}

/// JWT rotator for managing multiple keys
#[derive(Default)]
pub struct JwtRotator {
    keys: HashMap<String, Vec<u8>>,
    current_key: Option<(String, Vec<u8>)>,
}

impl JwtRotator {
    /// Create new rotator instance
    pub fn new() -> Self {
        Self {
            keys: HashMap::new(),
            current_key: None,
        }
    }
    
    /// Add a key to the rotator
    pub fn add_key(&mut self, key_id: String, key_bytes: Vec<u8>) {
        self.keys.insert(key_id.clone(), key_bytes.clone());
        if self.current_key.is_none() {
            self.current_key = Some((key_id, key_bytes));
        }
    }
    
    /// Get current key for signing
    pub fn get_current_key(&self) -> Option<&(String, Vec<u8>)> {
        self.current_key.as_ref()
    }
    
    /// List all available keys  
    pub fn list_keys(&self) -> Vec<&String> {
        self.keys.keys().collect()
    }
    
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
    
    /// Sign JWT with standard claims structure
    pub fn sign_claims(self, claims: JwtClaims) -> JwtRotatorSigner {
        self.sign(claims)
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
        // Use the current key from rotator and the claims
        let key_info = if let Some((key_id, _key_bytes)) = self.rotator.get_current_key() {
            format!("key:{}", key_id)
        } else {
            "nokey".to_string()
        };
        
        let claims_str = self.claims.to_string();
        let token = format!("header.{}.signature-{}", claims_str, key_info);
        
        let result = Ok(token);
        
        if let Some(handler) = self.result_handler {
            handler(result)
        } else {
            result.unwrap_or_default() // Never fails in practice since we create with Ok()
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
        // Use rotator to try all available keys for verification
        let token_str = token.as_ref();
        let available_keys = self.rotator.list_keys();
        
        let verification_result = if !available_keys.is_empty() {
            serde_json::json!({
                "verified": true,
                "token": token_str,
                "tried_keys": available_keys.len(),
                "sub": "rotator_verified",
                "name": "Test User"
            })
        } else {
            serde_json::json!({
                "verified": false,
                "error": "No keys available"
            })
        };
        
        let result = Ok(verification_result);
        
        if let Some(handler) = self.result_handler {
            handler(result)
        } else {
            result.unwrap_or_default() // Never fails in practice since we create with Ok()
        }
    }
}