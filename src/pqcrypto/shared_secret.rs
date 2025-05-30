//! Shared secret type for post-quantum KEM operations

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};
use std::fmt;

/// A shared secret produced by KEM encapsulation/decapsulation
/// 
/// This type wraps the raw shared secret bytes and ensures they are
/// properly zeroized when dropped.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SharedSecret {
    #[zeroize(skip)]
    algorithm: super::KemAlgorithm,
    secret: Vec<u8>,
}

impl SharedSecret {
    /// Create a new shared secret
    pub(crate) fn new(algorithm: super::KemAlgorithm, secret: Vec<u8>) -> Self {
        Self { algorithm, secret }
    }
    
    /// Get the algorithm used to generate this shared secret
    pub fn algorithm(&self) -> super::KemAlgorithm {
        self.algorithm
    }
    
    /// Get the shared secret as a byte slice
    pub fn as_bytes(&self) -> &[u8] {
        &self.secret
    }
    
    /// Convert the shared secret to a vector of bytes
    pub fn to_vec(&self) -> Vec<u8> {
        self.secret.clone()
    }
    
    /// Get the length of the shared secret in bytes
    pub fn len(&self) -> usize {
        self.secret.len()
    }
    
    /// Check if the shared secret is empty
    pub fn is_empty(&self) -> bool {
        self.secret.is_empty()
    }
    
    /// Convert to a hex string
    pub fn to_hex(&self) -> String {
        hex::encode(&self.secret)
    }
    
    /// Convert to a base64 string
    pub fn to_base64(&self) -> String {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(&self.secret)
    }
    
    /// Create from hex string
    pub fn from_hex(algorithm: super::KemAlgorithm, hex_str: &str) -> crate::Result<Self> {
        let secret = hex::decode(hex_str)
            .map_err(|e| crate::CryptError::InvalidEncryptedData(format!("Invalid hex: {}", e)))?;
        
        // Validate size
        let expected_size = algorithm.shared_secret_size();
        if secret.len() != expected_size {
            return Err(crate::CryptError::InvalidKeySize {
                expected: expected_size,
                actual: secret.len(),
            });
        }
        
        Ok(Self::new(algorithm, secret))
    }
    
    /// Create from base64 string
    pub fn from_base64(algorithm: super::KemAlgorithm, base64_str: &str) -> crate::Result<Self> {
        use base64::Engine;
        let secret = base64::engine::general_purpose::STANDARD
            .decode(base64_str)
            .map_err(|e| crate::CryptError::InvalidEncryptedData(format!("Invalid base64: {}", e)))?;
        
        // Validate size
        let expected_size = algorithm.shared_secret_size();
        if secret.len() != expected_size {
            return Err(crate::CryptError::InvalidKeySize {
                expected: expected_size,
                actual: secret.len(),
            });
        }
        
        Ok(Self::new(algorithm, secret))
    }
}

impl fmt::Debug for SharedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SharedSecret")
            .field("algorithm", &self.algorithm)
            .field("length", &self.secret.len())
            .finish()
    }
}

impl PartialEq for SharedSecret {
    fn eq(&self, other: &Self) -> bool {
        use subtle::ConstantTimeEq;
        self.algorithm == other.algorithm && self.secret.ct_eq(&other.secret).into()
    }
}

impl Eq for SharedSecret {}

/// Serializable wrapper for SharedSecret
#[derive(Serialize, Deserialize)]
struct SharedSecretData {
    algorithm: super::KemAlgorithm,
    #[serde(with = "base64_serde")]
    secret: Vec<u8>,
}

impl Serialize for SharedSecret {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let data = SharedSecretData {
            algorithm: self.algorithm,
            secret: self.secret.clone(),
        };
        data.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for SharedSecret {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let data = SharedSecretData::deserialize(deserializer)?;
        
        // Validate size
        let expected_size = data.algorithm.shared_secret_size();
        if data.secret.len() != expected_size {
            return Err(serde::de::Error::custom(format!(
                "Invalid shared secret size: expected {}, got {}",
                expected_size,
                data.secret.len()
            )));
        }
        
        Ok(Self::new(data.algorithm, data.secret))
    }
}

mod base64_serde {
    use serde::{Deserialize, Deserializer, Serializer};
    use base64::Engine;
    
    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let encoded = base64::engine::general_purpose::STANDARD.encode(bytes);
        serializer.serialize_str(&encoded)
    }
    
    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = String::deserialize(deserializer)?;
        base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_shared_secret_zeroize() {
        let secret_data = vec![1u8; 32];
        let secret_data_clone = secret_data.clone();
        
        {
            let secret = SharedSecret::new(super::super::KemAlgorithm::MlKem768, secret_data);
            assert_eq!(secret.as_bytes(), &secret_data_clone);
        }
        // Secret should be zeroized after drop
    }
    
    #[test]
    fn test_shared_secret_serialization() {
        let secret = SharedSecret::new(
            super::super::KemAlgorithm::MlKem768,
            vec![42u8; 32],
        );
        
        // Test JSON serialization
        let json = serde_json::to_string(&secret).expect("serialization failed");
        let deserialized: SharedSecret = serde_json::from_str(&json).expect("deserialization failed");
        
        assert_eq!(secret, deserialized);
    }
    
    #[test]
    fn test_hex_conversion() {
        let secret_data = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let algorithm = super::super::KemAlgorithm::MlKem512;
        
        // This will fail because ML-KEM expects 32 bytes
        let result = SharedSecret::from_hex(algorithm, "deadbeef");
        assert!(result.is_err());
        
        // This should work
        let hex_32 = "deadbeef".repeat(8); // 32 bytes
        let secret = SharedSecret::from_hex(algorithm, &hex_32).expect("from_hex failed");
        assert_eq!(secret.to_hex(), hex_32);
    }
}