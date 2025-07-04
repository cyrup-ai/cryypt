//! ES256 (ECDSA with P-256) JWT signing algorithm implementation.

use crate::{
    error::{JwtError, JwtResult},
    traits::{Header, Signer},
};
use p256::{
    ecdsa::{signature::Signer as _, signature::Verifier as _, SigningKey, VerifyingKey},
    elliptic_curve::rand_core::OsRng,
    pkcs8::EncodePublicKey,
};

/// ES256 (ECDSA with P-256) signing key.
pub struct Es256Key {
    sk: SigningKey, // Zeroizes on drop
    pk: VerifyingKey,
    kid: String,
}

impl Es256Key {
    /// Generate a new ES256 key pair.
    pub fn new() -> Self {
        let sk = SigningKey::random(&mut OsRng);
        let pk = *sk.verifying_key();
        let kid = match pk.to_public_key_der() {
            Ok(der) => base64_url::encode(der.as_bytes()),
            Err(_) => panic!("Failed to encode public key DER"),
        };
        Self { sk, pk, kid }
    }

    /// Set the key ID for this key.
    pub fn with_kid(mut self, kid: impl Into<String>) -> Self {
        self.kid = kid.into();
        self
    }

    /// Get the verifying (public) key.
    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.pk
    }

    /// Create from an existing signing key.
    pub fn from_signing_key(sk: SigningKey) -> Self {
        let pk = *sk.verifying_key();
        let kid = match pk.to_public_key_der() {
            Ok(der) => base64_url::encode(der.as_bytes()),
            Err(_) => panic!("Failed to encode public key DER"),
        };
        Self { sk, pk, kid }
    }
}

impl Default for Es256Key {
    fn default() -> Self {
        Self::new()
    }
}

impl Signer for Es256Key {
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
        let sig: p256::ecdsa::Signature = self.sk.sign(data.as_bytes());
        // Use fixed-length encoding for JWT (not DER)
        Ok(format!("{}.{}", data, base64_url::encode(&sig.to_bytes())))
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
        let sig_bytes = base64_url::decode(parts[2]).map_err(|_| JwtError::Malformed)?;
        let sig =
            p256::ecdsa::Signature::from_slice(&sig_bytes).map_err(|_| JwtError::Malformed)?;

        self.pk
            .verify(data.as_bytes(), &sig)
            .map_err(|_| JwtError::InvalidSignature)?;

        // Decode payload
        let payload_bytes = base64_url::decode(parts[1]).map_err(|_| JwtError::Malformed)?;
        let payload = String::from_utf8(payload_bytes).map_err(|_| JwtError::Malformed)?;
        Ok(payload)
    }

    fn alg(&self) -> &'static str {
        "ES256"
    }

    fn kid(&self) -> Option<String> {
        Some(self.kid.clone())
    }
}

