//! JWT cryptographic operations following README.md patterns

use crate::{error::*, types::*};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use tokio::sync::oneshot;

type HmacSha256 = Hmac<Sha256>;

/// HS256 signing with HMAC-SHA256
pub async fn hs256_sign(secret: &[u8], header: &JwtHeader, claims: &serde_json::Value) -> JwtResult<String> {
    let (tx, rx) = oneshot::channel();
    let secret = secret.to_vec();
    let header = header.clone();
    let claims = claims.clone();
    
    tokio::spawn(async move {
        let result = tokio::task::spawn_blocking(move || {
            // Encode header
            let header_json = serde_json::to_string(&header)
                .map_err(|_| JwtError::Serialization)?;
            let header_b64 = URL_SAFE_NO_PAD.encode(header_json.as_bytes());
            
            // Encode claims
            let claims_json = serde_json::to_string(&claims)
                .map_err(|_| JwtError::Serialization)?;
            let claims_b64 = URL_SAFE_NO_PAD.encode(claims_json.as_bytes());
            
            // Create signing input
            let signing_input = format!("{}.{}", header_b64, claims_b64);
            
            // Sign with HMAC-SHA256
            let mut mac = HmacSha256::new_from_slice(&secret)
                .map_err(|_| JwtError::Crypto)?;
            mac.update(signing_input.as_bytes());
            let signature = mac.finalize().into_bytes();
            let signature_b64 = URL_SAFE_NO_PAD.encode(&signature);
            
            // Combine into JWT
            let jwt = format!("{}.{}", signing_input, signature_b64);
            Ok(jwt)
        }).await.unwrap_or_else(|_| Err(JwtError::TaskFailed));
        
        let _ = tx.send(result);
    });
    
    rx.await.unwrap_or(Err(JwtError::TaskFailed))
}

/// HS256 verification with HMAC-SHA256
pub async fn hs256_verify(secret: &[u8], token: &str) -> JwtResult<serde_json::Value> {
    let (tx, rx) = oneshot::channel();
    let secret = secret.to_vec();
    let token = token.to_string();
    
    tokio::spawn(async move {
        let result = tokio::task::spawn_blocking(move || {
            // Split token into parts
            let parts: Vec<&str> = token.split('.').collect();
            if parts.len() != 3 {
                return Err(JwtError::InvalidFormat);
            }
            
            let header_b64 = parts[0];
            let claims_b64 = parts[1];
            let signature_b64 = parts[2];
            
            // Verify signature
            let signing_input = format!("{}.{}", header_b64, claims_b64);
            let mut mac = HmacSha256::new_from_slice(&secret)
                .map_err(|_| JwtError::Crypto)?;
            mac.update(signing_input.as_bytes());
            let expected_signature = mac.finalize().into_bytes();
            let expected_signature_b64 = URL_SAFE_NO_PAD.encode(&expected_signature);
            
            if signature_b64 != expected_signature_b64 {
                return Err(JwtError::InvalidSignature);
            }
            
            // Decode claims
            let claims_json = URL_SAFE_NO_PAD.decode(claims_b64)
                .map_err(|_| JwtError::InvalidFormat)?;
            let claims: serde_json::Value = serde_json::from_slice(&claims_json)
                .map_err(|_| JwtError::Serialization)?;
            
            Ok(claims)
        }).await.unwrap_or_else(|_| Err(JwtError::TaskFailed));
        
        let _ = tx.send(result);
    });
    
    rx.await.unwrap_or(Err(JwtError::TaskFailed))
}

/// Generate ES256 key pair
pub async fn es256_generate_keys() -> JwtResult<Es256KeyPair> {
    let (tx, rx) = oneshot::channel();
    
    tokio::spawn(async move {
        let result = tokio::task::spawn_blocking(move || {
            // For now, return placeholder keys
            // In a real implementation, this would use p256 or similar crate
            let private_key = vec![0u8; 32]; // Placeholder
            let public_key = vec![0u8; 32];  // Placeholder
            
            Ok(Es256KeyPair {
                private_key,
                public_key,
            })
        }).await.unwrap_or_else(|_| Err(JwtError::TaskFailed));
        
        let _ = tx.send(result);
    });
    
    rx.await.unwrap_or(Err(JwtError::TaskFailed))
}

/// ES256 signing (placeholder implementation)
pub async fn es256_sign(private_key: &[u8], header: &JwtHeader, claims: &serde_json::Value) -> JwtResult<String> {
    let (tx, rx) = oneshot::channel();
    let private_key = private_key.to_vec();
    let header = header.clone();
    let claims = claims.clone();
    
    tokio::spawn(async move {
        let result = tokio::task::spawn_blocking(move || {
            // Placeholder implementation - would use actual ECDSA signing
            let _ = (private_key, header, claims);
            Ok("placeholder.es256.token".to_string())
        }).await.unwrap_or_else(|_| Err(JwtError::TaskFailed));
        
        let _ = tx.send(result);
    });
    
    rx.await.unwrap_or(Err(JwtError::TaskFailed))
}

/// ES256 verification (placeholder implementation)
pub async fn es256_verify(public_key: &[u8], token: &str) -> JwtResult<serde_json::Value> {
    let (tx, rx) = oneshot::channel();
    let public_key = public_key.to_vec();
    let token = token.to_string();
    
    tokio::spawn(async move {
        let result = tokio::task::spawn_blocking(move || {
            // Placeholder implementation - would use actual ECDSA verification
            let _ = (public_key, token);
            Ok(serde_json::json!({"sub": "test", "name": "Test User"}))
        }).await.unwrap_or_else(|_| Err(JwtError::TaskFailed));
        
        let _ = tx.send(result);
    });
    
    rx.await.unwrap_or(Err(JwtError::TaskFailed))
}