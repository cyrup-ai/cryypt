//! HS256 (HMAC-SHA256) JWT signing algorithm implementation.

use crate::jwt::{
    error::{JwtError, JwtResult},
    traits::{Header, Signer},
};
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

type HmacSha256 = Hmac<Sha256>;

/// Constant-time zeroizable secret for HS256.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Hs256Key {
    key: [u8; 32],
    kid: Option<String>,
}

impl Hs256Key {
    /// Generate a new random HS256 key.
    pub fn random() -> Self {
        let mut k = [0u8; 32];
        rand::rng().fill_bytes(&mut k);
        Self { key: k, kid: None }
    }

    /// Set the key ID for this key.
    pub fn with_kid(mut self, kid: impl Into<String>) -> Self {
        self.kid = Some(kid.into());
        self
    }

    /// Create from raw bytes.
    pub fn from_bytes(key: [u8; 32]) -> Self {
        Self { key, kid: None }
    }
}

impl Signer for Hs256Key {
    fn sign(&self, header: &Header, payload: &str) -> JwtResult<String> {
        let header_json = match serde_json::to_string(header) {
            Ok(h) => h,
            Err(_) => return Err(JwtError::Malformed),
        };
        let data = format!(
            "{}.{}",
            base64_url::encode(&header_json),
            base64_url::encode(payload)
        );

        let mut mac =
            HmacSha256::new_from_slice(&self.key).map_err(|e| JwtError::Crypto(e.to_string()))?;
        mac.update(data.as_bytes());
        let sig = mac.finalize().into_bytes();
        Ok(format!("{}.{}", data, base64_url::encode(&sig)))
    }

    fn verify(&self, token: &str) -> JwtResult<String> {
        // Split token
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return Err(JwtError::Malformed);
        }

        // Parse and validate header
        let header_bytes = base64_url::decode(parts[0]).map_err(|_| JwtError::Malformed)?;

        // Parse header to extract algorithm
        let header_json: serde_json::Value =
            serde_json::from_slice(&header_bytes).map_err(|_| JwtError::Malformed)?;
        let header_alg = header_json["alg"]
            .as_str()
            .ok_or(JwtError::Malformed)?
            .to_string();

        // Verify algorithm matches
        if header_alg != self.alg() {
            return Err(JwtError::AlgorithmMismatch {
                expected: self.alg().to_string(),
                got: header_alg,
            });
        }

        // Verify signature
        let data = format!("{}.{}", parts[0], parts[1]);
        let sig = base64_url::decode(parts[2]).map_err(|_| JwtError::Malformed)?;

        let mut mac =
            HmacSha256::new_from_slice(&self.key).map_err(|e| JwtError::Crypto(e.to_string()))?;
        mac.update(data.as_bytes());
        mac.verify_slice(&sig)
            .map_err(|_| JwtError::InvalidSignature)?;

        // Decode payload
        let payload_bytes = base64_url::decode(parts[1]).map_err(|_| JwtError::Malformed)?;
        let payload = String::from_utf8(payload_bytes).map_err(|_| JwtError::Malformed)?;
        Ok(payload)
    }

    fn alg(&self) -> &'static str {
        "HS256"
    }

    fn kid(&self) -> Option<String> {
        self.kid.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jwt::claims::{Claims, ClaimsBuilder};
    use chrono::Duration;

    #[test]
    fn test_hs256_key_generation() {
        let key = Hs256Key::random();
        assert_eq!(key.alg(), "HS256");
        assert!(key.kid().is_none());

        let key_with_kid = Hs256Key::random().with_kid("test-key");
        assert_eq!(key_with_kid.kid(), Some("test-key".to_string()));
    }

    #[test]
    fn test_hs256_sign_verify_roundtrip() {
        let key = Hs256Key::random();
        let header = Header::new("HS256", Some("test-key".to_string()));
        let payload = r#"{"sub":"user123","exp":1234567890}"#;

        let token = key.sign(&header, payload).unwrap();
        assert!(!token.is_empty());
        assert_eq!(token.matches('.').count(), 2);

        let verified_payload = key.verify(&token).unwrap();
        assert_eq!(verified_payload, payload);
    }

    #[test]
    fn test_hs256_invalid_signature() {
        let key1 = Hs256Key::random();
        let key2 = Hs256Key::random();
        let header = Header::new("HS256", None);
        let payload = r#"{"sub":"user123"}"#;

        // Sign with key1
        let token = key1.sign(&header, payload).unwrap();

        // Try to verify with key2 (should fail)
        let result = key2.verify(&token);
        assert!(matches!(result, Err(JwtError::InvalidSignature)));
    }

    #[test]
    fn test_hs256_algorithm_mismatch() {
        let key = Hs256Key::random();

        // Create a token with wrong algorithm in header
        let wrong_header = Header::new("RS256", None);
        let header_json = serde_json::to_string(&wrong_header).unwrap();
        let payload = r#"{"sub":"user123"}"#;

        // Manually create token with wrong algorithm
        let data = format!(
            "{}.{}",
            base64_url::encode(&header_json),
            base64_url::encode(payload)
        );
        let fake_token = format!("{}.fakesignature", data);

        let result = key.verify(&fake_token);
        assert!(matches!(result, Err(JwtError::AlgorithmMismatch { .. })));
    }
}
