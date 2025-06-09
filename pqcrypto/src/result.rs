//! Result types for post-quantum cryptography operations

use crate::{CryptError, Result};
use serde::{Deserialize, Serialize};

/// Result of a KEM encapsulation operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncapsulationResult {
    /// The algorithm used
    algorithm: super::KemAlgorithm,
    /// The encapsulated ciphertext to send to the decapsulator
    #[serde(with = "base64_serde")]
    ciphertext: Vec<u8>,
    /// The shared secret (not sent, kept by encapsulator)
    #[serde(skip)]
    shared_secret: super::SharedSecret,
}

impl EncapsulationResult {
    /// Create a new encapsulation result
    pub(crate) fn new(
        algorithm: super::KemAlgorithm,
        ciphertext: Vec<u8>,
        shared_secret: super::SharedSecret,
    ) -> Self {
        Self {
            algorithm,
            ciphertext,
            shared_secret,
        }
    }

    /// Get the algorithm used
    pub fn algorithm(&self) -> super::KemAlgorithm {
        self.algorithm
    }

    /// Get the ciphertext as bytes
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    /// Get the ciphertext as a vector
    pub fn ciphertext_vec(&self) -> Vec<u8> {
        self.ciphertext.clone()
    }

    /// Get the shared secret
    pub fn shared_secret(&self) -> &super::SharedSecret {
        &self.shared_secret
    }

    /// Convert ciphertext to hex string
    pub fn ciphertext_hex(&self) -> String {
        hex::encode(&self.ciphertext)
    }

    /// Convert ciphertext to base64 string
    pub fn ciphertext_base64(&self) -> String {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(&self.ciphertext)
    }

    /// Get the size of the ciphertext in bytes
    pub fn ciphertext_size(&self) -> usize {
        self.ciphertext.len()
    }
}

/// Result of a KEM decapsulation operation
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecapsulationResult {
    /// The algorithm used
    algorithm: super::KemAlgorithm,
    /// The recovered shared secret
    shared_secret: super::SharedSecret,
}

impl DecapsulationResult {
    /// Create a new decapsulation result
    pub(crate) fn new(algorithm: super::KemAlgorithm, shared_secret: super::SharedSecret) -> Self {
        Self {
            algorithm,
            shared_secret,
        }
    }

    /// Get the algorithm used
    pub fn algorithm(&self) -> super::KemAlgorithm {
        self.algorithm
    }

    /// Get the shared secret
    pub fn shared_secret(&self) -> &super::SharedSecret {
        &self.shared_secret
    }

    /// Convert to owned shared secret
    pub fn into_shared_secret(self) -> super::SharedSecret {
        self.shared_secret
    }
}

/// Result of a digital signature operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureResult {
    /// The algorithm used
    algorithm: super::SignatureAlgorithm,
    /// The signature bytes
    #[serde(with = "base64_serde")]
    signature: Vec<u8>,
    /// The message that was signed (optional, for detached signatures)
    #[serde(skip_serializing_if = "Option::is_none", with = "option_base64_serde")]
    message: Option<Vec<u8>>,
}

impl SignatureResult {
    /// Create a new signature result
    pub(crate) fn new(
        algorithm: super::SignatureAlgorithm,
        signature: Vec<u8>,
        message: Option<Vec<u8>>,
    ) -> Self {
        Self {
            algorithm,
            signature,
            message,
        }
    }

    /// Get the algorithm used
    pub fn algorithm(&self) -> super::SignatureAlgorithm {
        self.algorithm
    }

    /// Get the signature as bytes
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }

    /// Get the signature as a vector
    pub fn signature_vec(&self) -> Vec<u8> {
        self.signature.clone()
    }

    /// Get the message if included (for non-detached signatures)
    pub fn message(&self) -> Option<&[u8]> {
        self.message.as_deref()
    }

    /// Convert signature to hex string
    pub fn signature_hex(&self) -> String {
        hex::encode(&self.signature)
    }

    /// Convert signature to base64 string
    pub fn signature_base64(&self) -> String {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(&self.signature)
    }

    /// Get the size of the signature in bytes
    pub fn signature_size(&self) -> usize {
        self.signature.len()
    }

    /// Check if this is a detached signature
    pub fn is_detached(&self) -> bool {
        self.message.is_none()
    }
}

/// Result of a signature verification operation
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationResult {
    /// The algorithm used
    algorithm: super::SignatureAlgorithm,
    /// Whether the signature is valid
    is_valid: bool,
    /// The verified message (if applicable)
    message: Option<Vec<u8>>,
}

impl VerificationResult {
    /// Create a new verification result
    pub(crate) fn new(
        algorithm: super::SignatureAlgorithm,
        is_valid: bool,
        message: Option<Vec<u8>>,
    ) -> Self {
        Self {
            algorithm,
            is_valid,
            message,
        }
    }

    /// Get the algorithm used
    pub fn algorithm(&self) -> super::SignatureAlgorithm {
        self.algorithm
    }

    /// Check if the signature is valid
    pub fn is_valid(&self) -> bool {
        self.is_valid
    }

    /// Get the verified message (if any)
    pub fn message(&self) -> Option<&[u8]> {
        self.message.as_deref()
    }

    /// Convert to a Result type, returning an error if invalid
    pub fn to_result(self) -> Result<Option<Vec<u8>>> {
        if self.is_valid {
            Ok(self.message)
        } else {
            Err(CryptError::AuthenticationFailed(
                "Signature verification failed".to_string(),
            ))
        }
    }
}

/// Helper module for base64 serde
mod base64_serde {
    use base64::Engine;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8], serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let encoded = base64::engine::general_purpose::STANDARD.encode(bytes);
        serializer.serialize_str(&encoded)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> std::result::Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = String::deserialize(deserializer)?;
        base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(serde::de::Error::custom)
    }
}

/// Helper module for optional base64 serde
mod option_base64_serde {
    use base64::Engine;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(
        value: &Option<Vec<u8>>,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match value {
            Some(bytes) => {
                let encoded = base64::engine::general_purpose::STANDARD.encode(bytes);
                serializer.serialize_some(&encoded)
            }
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> std::result::Result<Option<Vec<u8>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt_str = Option::<String>::deserialize(deserializer)?;
        match opt_str {
            Some(encoded) => {
                let decoded = base64::engine::general_purpose::STANDARD
                    .decode(encoded)
                    .map_err(serde::de::Error::custom)?;
                Ok(Some(decoded))
            }
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encapsulation_result_serialization() {
        let shared_secret =
            super::super::SharedSecret::new(super::super::KemAlgorithm::MlKem768, vec![42u8; 32]);
        let result = EncapsulationResult::new(
            super::super::KemAlgorithm::MlKem768,
            vec![1u8; 1088], // ML-KEM-768 ciphertext size
            shared_secret,
        );

        // Test JSON serialization (shared secret should be skipped)
        let json = serde_json::to_string(&result).expect("serialization failed");
        assert!(!json.contains("shared_secret"));

        let deserialized: serde_json::Value =
            serde_json::from_str(&json).expect("deserialization failed");
        assert!(deserialized.get("ciphertext").is_some());
        assert!(deserialized.get("algorithm").is_some());
    }

    #[test]
    fn test_verification_result_to_result() {
        let valid_result = VerificationResult::new(
            super::super::SignatureAlgorithm::MlDsa65,
            true,
            Some(b"message".to_vec()),
        );

        assert!(valid_result.to_result().is_ok());

        let invalid_result =
            VerificationResult::new(super::super::SignatureAlgorithm::MlDsa65, false, None);

        assert!(invalid_result.to_result().is_err());
    }
}
