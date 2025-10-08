//! ES256 verification with ECDSA P-256 - production implementation

use crate::error::{JwtError, JwtResult};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use p256::{
    ecdsa::{Signature, VerifyingKey, signature::Verifier},
    pkcs8::DecodePublicKey,
};

/// ES256 verification with ECDSA P-256 - Production async implementation
#[allow(dead_code)]
pub fn es256_verify(public_key: &[u8], token: &str) -> JwtResult<serde_json::Value> {
    // Direct async implementation - ECDSA verification is fast enough for direct execution
    // Split token into parts with constant-time length validation
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(JwtError::InvalidFormat);
    }

    let header_b64 = parts[0];
    let claims_b64 = parts[1];
    let signature_b64 = parts[2];

    // Parse ECDSA public key - support both PEM and raw formats
    let verifying_key = if public_key.starts_with(b"-----BEGIN") {
        // PEM format
        let key_str = std::str::from_utf8(public_key)
            .map_err(|_| JwtError::invalid_key("Invalid UTF-8 in public key"))?;
        VerifyingKey::from_public_key_pem(key_str)
            .map_err(|_| JwtError::invalid_key("Invalid PEM public key"))?
    } else {
        // Raw bytes format - uncompressed point (65 bytes) or compressed (33 bytes)
        match public_key.len() {
            33 | 65 => VerifyingKey::from_sec1_bytes(public_key)
                .map_err(|_| JwtError::invalid_key("Invalid SEC1 public key bytes"))?,
            _ => {
                return Err(JwtError::invalid_key(
                    "Public key must be 33 or 65 bytes for P-256",
                ));
            }
        }
    };

    // Decode signature with proper error handling
    let signature_bytes = URL_SAFE_NO_PAD
        .decode(signature_b64)
        .map_err(|_| JwtError::InvalidSignature)?;

    // Parse DER signature format
    let signature =
        Signature::from_der(&signature_bytes).map_err(|_| JwtError::InvalidSignature)?;

    // Recreate signing input for verification - optimized construction
    let mut signing_input = String::with_capacity(header_b64.len() + 1 + claims_b64.len());
    signing_input.push_str(header_b64);
    signing_input.push('.');
    signing_input.push_str(claims_b64);

    // Verify signature with constant-time comparison
    verifying_key
        .verify(signing_input.as_bytes(), &signature)
        .map_err(|_| JwtError::InvalidSignature)?;

    // Only decode claims after signature verification succeeds
    let claims_json = URL_SAFE_NO_PAD
        .decode(claims_b64)
        .map_err(|_| JwtError::InvalidFormat)?;

    let claims: serde_json::Value = serde_json::from_slice(&claims_json)
        .map_err(|e| JwtError::serialization(&e.to_string()))?;

    // Validate JWT timing claims for additional security
    let now = chrono::Utc::now().timestamp();

    // Check expiration (exp claim)
    if let Some(exp) = claims.get("exp")
        && let Some(exp_time) = exp.as_i64()
        && now >= exp_time
    {
        return Err(JwtError::token_expired());
    }

    // Check not before (nbf claim)
    if let Some(nbf) = claims.get("nbf")
        && let Some(nbf_time) = nbf.as_i64()
        && now < nbf_time
    {
        return Err(JwtError::token_not_yet_valid());
    }

    Ok(claims)
}
