//! KEM (Key Encapsulation Mechanism) builder implementations

use crate::{CryptError, Result};
use super::{
    builder_traits::*,
    states::*,
};
use super::super::{
    KemAlgorithm, EncapsulationResult, DecapsulationResult, SharedSecret,
};
use std::marker::PhantomData;

/// Main entry point for KEM operations
pub struct KemBuilder;

impl KemBuilder {
    /// Create a new ML-KEM builder with the specified security level
    pub fn ml_kem(security_level: u16) -> Result<MlKemBuilder<NeedKeyPair>> {
        let algorithm = match security_level {
            512 => KemAlgorithm::MlKem512,
            768 => KemAlgorithm::MlKem768,
            1024 => KemAlgorithm::MlKem1024,
            _ => return Err(CryptError::UnsupportedAlgorithm(
                format!("ML-KEM-{} is not supported. Use 512, 768, or 1024", security_level)
            )),
        };
        
        Ok(MlKemBuilder {
            algorithm,
            state: PhantomData,
            public_key: None,
            secret_key: None,
            ciphertext: None,
        })
    }
    
    /// Create ML-KEM-512 builder (NIST security level 1)
    pub fn ml_kem_512() -> MlKemBuilder<NeedKeyPair> {
        MlKemBuilder {
            algorithm: KemAlgorithm::MlKem512,
            state: PhantomData,
            public_key: None,
            secret_key: None,
            ciphertext: None,
        }
    }
    
    /// Create ML-KEM-768 builder (NIST security level 3)
    pub fn ml_kem_768() -> MlKemBuilder<NeedKeyPair> {
        MlKemBuilder {
            algorithm: KemAlgorithm::MlKem768,
            state: PhantomData,
            public_key: None,
            secret_key: None,
            ciphertext: None,
        }
    }
    
    /// Create ML-KEM-1024 builder (NIST security level 5)
    pub fn ml_kem_1024() -> MlKemBuilder<NeedKeyPair> {
        MlKemBuilder {
            algorithm: KemAlgorithm::MlKem1024,
            state: PhantomData,
            public_key: None,
            secret_key: None,
            ciphertext: None,
        }
    }
}

/// ML-KEM builder type
pub struct MlKemBuilder<State> {
    algorithm: KemAlgorithm,
    state: PhantomData<State>,
    public_key: Option<Vec<u8>>,
    secret_key: Option<Vec<u8>>,
    ciphertext: Option<Vec<u8>>,
}

impl<State> MlKemBuilder<State> {
    /// Validate key sizes
    fn validate_public_key(&self, key: &[u8]) -> Result<()> {
        let expected = self.algorithm.public_key_size();
        if key.len() != expected {
            return Err(CryptError::InvalidKeySize {
                expected,
                actual: key.len(),
            });
        }
        Ok(())
    }
    
    fn validate_secret_key(&self, key: &[u8]) -> Result<()> {
        let expected = self.algorithm.secret_key_size();
        if key.len() != expected {
            return Err(CryptError::InvalidKeySize {
                expected,
                actual: key.len(),
            });
        }
        Ok(())
    }
    
    fn validate_ciphertext(&self, ct: &[u8]) -> Result<()> {
        let expected = self.algorithm.ciphertext_size();
        if ct.len() != expected {
            return Err(CryptError::InvalidEncryptedData(format!(
                "Invalid ciphertext size: expected {}, got {}",
                expected,
                ct.len()
            )));
        }
        Ok(())
    }
}

// Implementation for NeedKeyPair state
impl KemKeyPairBuilder for MlKemBuilder<NeedKeyPair> {
    type Output = MlKemBuilder<HasKeyPair>;
    
    async fn generate(self) -> Result<Self::Output> {
        use rand::rngs::OsRng;
        
        let (pk, sk) = match self.algorithm {
            KemAlgorithm::MlKem512 => {
                let (pk, sk) = pqcrypto_mlkem::mlkem512::keypair();
                (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
            }
            KemAlgorithm::MlKem768 => {
                let (pk, sk) = pqcrypto_mlkem::mlkem768::keypair();
                (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
            }
            KemAlgorithm::MlKem1024 => {
                let (pk, sk) = pqcrypto_mlkem::mlkem1024::keypair();
                (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
            }
        };
        
        Ok(MlKemBuilder {
            algorithm: self.algorithm,
            state: PhantomData,
            public_key: Some(pk),
            secret_key: Some(sk),
            ciphertext: None,
        })
    }
    
    fn with_keypair<T: Into<Vec<u8>>>(self, public_key: T, secret_key: T) -> Result<Self::Output> {
        let pk = public_key.into();
        let sk = secret_key.into();
        
        self.validate_public_key(&pk)?;
        self.validate_secret_key(&sk)?;
        
        Ok(MlKemBuilder {
            algorithm: self.algorithm,
            state: PhantomData,
            public_key: Some(pk),
            secret_key: Some(sk),
            ciphertext: None,
        })
    }
    
    fn with_public_key<T: Into<Vec<u8>>>(self, public_key: T) -> Result<MlKemBuilder<HasPublicKey>> {
        let pk = public_key.into();
        self.validate_public_key(&pk)?;
        
        Ok(MlKemBuilder {
            algorithm: self.algorithm,
            state: PhantomData,
            public_key: Some(pk),
            secret_key: None,
            ciphertext: None,
        })
    }
    
    fn with_secret_key<T: Into<Vec<u8>>>(self, secret_key: T) -> Result<MlKemBuilder<HasSecretKey>> {
        let sk = secret_key.into();
        self.validate_secret_key(&sk)?;
        
        Ok(MlKemBuilder {
            algorithm: self.algorithm,
            state: PhantomData,
            public_key: None,
            secret_key: Some(sk),
            ciphertext: None,
        })
    }
}

// Type aliases for better readability
pub type MlKemWithKeyPair = MlKemBuilder<HasKeyPair>;
pub type MlKemWithPublicKey = MlKemBuilder<HasPublicKey>;
pub type MlKemWithSecretKey = MlKemBuilder<HasSecretKey>;
pub type MlKemWithCiphertext = MlKemBuilder<HasCiphertext>;

// Implementation for HasPublicKey state - can encapsulate
impl EncapsulateBuilder for MlKemBuilder<HasPublicKey> {
    async fn encapsulate(self) -> Result<EncapsulationResult> {
        let public_key = self.public_key
            .ok_or_else(|| CryptError::InternalError("Public key not set".to_string()))?;
        
        let (shared_secret_bytes, ciphertext) = match self.algorithm {
            KemAlgorithm::MlKem512 => {
                use pqcrypto_mlkem::mlkem512::{PublicKey, encapsulate};
                let pk = PublicKey::from_bytes(&public_key)
                    .map_err(|_| CryptError::InvalidKey("Invalid ML-KEM-512 public key".to_string()))?;
                let (ss, ct) = encapsulate(&pk);
                (ss.as_bytes().to_vec(), ct.as_bytes().to_vec())
            }
            KemAlgorithm::MlKem768 => {
                use pqcrypto_mlkem::mlkem768::{PublicKey, encapsulate};
                let pk = PublicKey::from_bytes(&public_key)
                    .map_err(|_| CryptError::InvalidKey("Invalid ML-KEM-768 public key".to_string()))?;
                let (ss, ct) = encapsulate(&pk);
                (ss.as_bytes().to_vec(), ct.as_bytes().to_vec())
            }
            KemAlgorithm::MlKem1024 => {
                use pqcrypto_mlkem::mlkem1024::{PublicKey, encapsulate};
                let pk = PublicKey::from_bytes(&public_key)
                    .map_err(|_| CryptError::InvalidKey("Invalid ML-KEM-1024 public key".to_string()))?;
                let (ss, ct) = encapsulate(&pk);
                (ss.as_bytes().to_vec(), ct.as_bytes().to_vec())
            }
        };
        
        let shared_secret = SharedSecret::new(self.algorithm, shared_secret_bytes);
        Ok(EncapsulationResult::new(self.algorithm, ciphertext, shared_secret))
    }
}

// Implementation for HasKeyPair state - can encapsulate or add ciphertext for decapsulation
impl EncapsulateBuilder for MlKemBuilder<HasKeyPair> {
    async fn encapsulate(self) -> Result<EncapsulationResult> {
        MlKemBuilder::<HasPublicKey> {
            algorithm: self.algorithm,
            state: PhantomData,
            public_key: self.public_key,
            secret_key: None,
            ciphertext: None,
        }.encapsulate().await
    }
}

impl CiphertextBuilder for MlKemBuilder<HasSecretKey> {
    type Output = MlKemBuilder<HasCiphertext>;
    
    fn with_ciphertext<T: Into<Vec<u8>>>(self, ciphertext: T) -> Self::Output {
        MlKemBuilder {
            algorithm: self.algorithm,
            state: PhantomData,
            public_key: self.public_key,
            secret_key: self.secret_key,
            ciphertext: Some(ciphertext.into()),
        }
    }
}

impl CiphertextBuilder for MlKemBuilder<HasKeyPair> {
    type Output = MlKemBuilder<HasCiphertext>;
    
    fn with_ciphertext<T: Into<Vec<u8>>>(self, ciphertext: T) -> Self::Output {
        MlKemBuilder {
            algorithm: self.algorithm,
            state: PhantomData,
            public_key: self.public_key,
            secret_key: self.secret_key,
            ciphertext: Some(ciphertext.into()),
        }
    }
}

// Implementation for HasCiphertext state - can decapsulate if has secret key
impl DecapsulateBuilder for MlKemBuilder<HasCiphertext> {
    async fn decapsulate(self) -> Result<DecapsulationResult> {
        let secret_key = self.secret_key
            .ok_or_else(|| CryptError::InvalidKey("Secret key required for decapsulation".to_string()))?;
        let ciphertext = self.ciphertext
            .ok_or_else(|| CryptError::InternalError("Ciphertext not set".to_string()))?;
        
        self.validate_ciphertext(&ciphertext)?;
        
        let shared_secret_bytes = match self.algorithm {
            KemAlgorithm::MlKem512 => {
                use pqcrypto_mlkem::mlkem512::{SecretKey, Ciphertext, decapsulate};
                let sk = SecretKey::from_bytes(&secret_key)
                    .map_err(|_| CryptError::InvalidKey("Invalid ML-KEM-512 secret key".to_string()))?;
                let ct = Ciphertext::from_bytes(&ciphertext)
                    .map_err(|_| CryptError::InvalidEncryptedData("Invalid ML-KEM-512 ciphertext".to_string()))?;
                let ss = decapsulate(&ct, &sk);
                ss.as_bytes().to_vec()
            }
            KemAlgorithm::MlKem768 => {
                use pqcrypto_mlkem::mlkem768::{SecretKey, Ciphertext, decapsulate};
                let sk = SecretKey::from_bytes(&secret_key)
                    .map_err(|_| CryptError::InvalidKey("Invalid ML-KEM-768 secret key".to_string()))?;
                let ct = Ciphertext::from_bytes(&ciphertext)
                    .map_err(|_| CryptError::InvalidEncryptedData("Invalid ML-KEM-768 ciphertext".to_string()))?;
                let ss = decapsulate(&ct, &sk);
                ss.as_bytes().to_vec()
            }
            KemAlgorithm::MlKem1024 => {
                use pqcrypto_mlkem::mlkem1024::{SecretKey, Ciphertext, decapsulate};
                let sk = SecretKey::from_bytes(&secret_key)
                    .map_err(|_| CryptError::InvalidKey("Invalid ML-KEM-1024 secret key".to_string()))?;
                let ct = Ciphertext::from_bytes(&ciphertext)
                    .map_err(|_| CryptError::InvalidEncryptedData("Invalid ML-KEM-1024 ciphertext".to_string()))?;
                let ss = decapsulate(&ct, &sk);
                ss.as_bytes().to_vec()
            }
        };
        
        let shared_secret = SharedSecret::new(self.algorithm, shared_secret_bytes);
        Ok(DecapsulationResult::new(self.algorithm, shared_secret))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_ml_kem_builder_creation() {
        // Test all security levels
        assert!(KemBuilder::ml_kem(512).is_ok());
        assert!(KemBuilder::ml_kem(768).is_ok());
        assert!(KemBuilder::ml_kem(1024).is_ok());
        assert!(KemBuilder::ml_kem(2048).is_err());
        
        // Test convenience methods
        let _ = KemBuilder::ml_kem_512();
        let _ = KemBuilder::ml_kem_768();
        let _ = KemBuilder::ml_kem_1024();
    }
}