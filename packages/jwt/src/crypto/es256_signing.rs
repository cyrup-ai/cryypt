//! ES256 signing with ECDSA P-256 - production implementation

use crate::{
    error::{JwtError, JwtResult},
    types::JwtHeader,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use p256::{
    ecdsa::{Signature, SigningKey, signature::Signer},
    pkcs8::DecodePrivateKey,
};
/// ES256 signing with ECDSA P-256 - Production async implementation
#[allow(dead_code)]
pub fn es256_sign(
    private_key: &[u8],
    header: &JwtHeader,
    claims: &serde_json::Value,
) -> JwtResult<String> {
    // Direct async implementation using fast ECDSA operations suitable for async context
    // Parse ECDSA private key - support both PEM and raw formats
    let signing_key = if private_key.starts_with(b"-----BEGIN") {
        // PEM format
        let key_str = std::str::from_utf8(private_key)
            .map_err(|_| JwtError::invalid_key("Invalid UTF-8 in private key"))?;
        SigningKey::from_pkcs8_pem(key_str)
            .map_err(|_| JwtError::invalid_key("Invalid PKCS8 PEM private key"))?
    } else {
        // Raw bytes format (32 bytes for P-256)
        if private_key.len() != 32 {
            return Err(JwtError::invalid_key(
                "Private key must be 32 bytes for P-256",
            ));
        }
        // Convert &[u8] to correct array type for P-256
        let key_bytes: [u8; 32] = private_key
            .try_into()
            .map_err(|_| JwtError::invalid_key("Invalid P-256 private key length"))?;
        SigningKey::from_bytes(&key_bytes.into())
            .map_err(|_| JwtError::invalid_key("Invalid P-256 private key bytes"))?
    };

    // Encode header to base64url (zero-allocation where possible)
    let header_json =
        serde_json::to_vec(&header).map_err(|e| JwtError::serialization(&e.to_string()))?;
    let header_b64 = URL_SAFE_NO_PAD.encode(&header_json);

    // Encode claims to base64url (zero-allocation where possible)
    let claims_json =
        serde_json::to_vec(&claims).map_err(|e| JwtError::serialization(&e.to_string()))?;
    let claims_b64 = URL_SAFE_NO_PAD.encode(&claims_json);

    // Create signing input - optimized string construction
    let mut signing_input = String::with_capacity(header_b64.len() + 1 + claims_b64.len());
    signing_input.push_str(&header_b64);
    signing_input.push('.');
    signing_input.push_str(&claims_b64);

    // Sign with ECDSA P-256 - constant time operations, fast enough for direct async
    let signature: Signature = signing_key.sign(signing_input.as_bytes());
    let signature_bytes = signature.to_der();
    let signature_b64 = URL_SAFE_NO_PAD.encode(&signature_bytes);

    // Combine into JWT - optimized final construction
    let mut jwt = String::with_capacity(signing_input.len() + 1 + signature_b64.len());
    jwt.push_str(&signing_input);
    jwt.push('.');
    jwt.push_str(&signature_b64);

    Ok(jwt)
}
