//! HMAC-SHA256 operations for JWT signing and verification

use crate::error::{JwtError, JwtResult};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// HS256 verification with HMAC-SHA256 - Production async implementation
pub fn hs256_verify(secret: &[u8], token: &str) -> JwtResult<serde_json::Value> {
    // Direct async implementation using fast HMAC operations suitable for async context
    // Split token into parts
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(JwtError::InvalidFormat);
    }

    let header_b64 = parts[0];
    let claims_b64 = parts[1];
    let signature_b64 = parts[2];

    // Verify signature
    let signing_input = format!("{header_b64}.{claims_b64}");
    let mut mac = HmacSha256::new_from_slice(secret).map_err(|_| JwtError::Crypto)?;
    mac.update(signing_input.as_bytes());
    let expected_signature = mac.finalize().into_bytes();
    let expected_signature_b64 = URL_SAFE_NO_PAD.encode(expected_signature);

    if signature_b64 != expected_signature_b64 {
        return Err(JwtError::InvalidSignature);
    }

    // Decode claims
    let claims_json = URL_SAFE_NO_PAD
        .decode(claims_b64)
        .map_err(|_| JwtError::InvalidFormat)?;
    let claims: serde_json::Value = serde_json::from_slice(&claims_json)
        .map_err(|e| JwtError::serialization(&e.to_string()))?;

    Ok(claims)
}

/// Production HMAC-SHA256 signing for raw bytes
pub fn hmac_sha256_sign(data: &[u8], secret: &[u8]) -> JwtResult<Vec<u8>> {
    let mut mac = HmacSha256::new_from_slice(secret)
        .map_err(|_| JwtError::InvalidKey("Invalid HMAC key".to_string()))?;
    mac.update(data);
    Ok(mac.finalize().into_bytes().to_vec())
}
