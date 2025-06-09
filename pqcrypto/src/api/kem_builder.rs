//! KEM (Key Encapsulation Mechanism) builder implementations

use super::super::{DecapsulationResult, EncapsulationResult, KemAlgorithm, SharedSecret};
use super::{builder_traits::*, states::*};
use crate::{CryptError, Result};
use pqcrypto_traits::kem::{
    Ciphertext as PqCiphertext, PublicKey as PqPublicKey, SecretKey as PqSecretKey,
    SharedSecret as PqSharedSecret,
};
use std::future::Future;
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
            _ => {
                return Err(CryptError::UnsupportedAlgorithm(format!(
                    "ML-KEM-{} is not supported. Use 512, 768, or 1024",
                    security_level
                )));
            }
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
}

// Implementation for NeedKeyPair state
impl KemKeyPairBuilder for MlKemBuilder<NeedKeyPair> {
    type Output = MlKemBuilder<HasKeyPair>;
    type PublicKeyOutput = MlKemBuilder<HasPublicKey>;
    type SecretKeyOutput = MlKemBuilder<HasSecretKey>;

    fn generate(self) -> impl Future<Output = Result<Self::Output>> + Send {
        async move {
            let (pk, sk) = match self.algorithm {
                KemAlgorithm::MlKem512 => {
                    let (pk, sk) = pqcrypto_mlkem::mlkem512::keypair();
                    (
                        PqPublicKey::as_bytes(&pk).to_vec(),
                        PqSecretKey::as_bytes(&sk).to_vec(),
                    )
                }
                KemAlgorithm::MlKem768 => {
                    let (pk, sk) = pqcrypto_mlkem::mlkem768::keypair();
                    (
                        PqPublicKey::as_bytes(&pk).to_vec(),
                        PqSecretKey::as_bytes(&sk).to_vec(),
                    )
                }
                KemAlgorithm::MlKem1024 => {
                    let (pk, sk) = pqcrypto_mlkem::mlkem1024::keypair();
                    (
                        PqPublicKey::as_bytes(&pk).to_vec(),
                        PqSecretKey::as_bytes(&sk).to_vec(),
                    )
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

    fn with_public_key<T: Into<Vec<u8>>>(
        self,
        public_key: T,
    ) -> Result<MlKemBuilder<HasPublicKey>> {
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

    fn with_secret_key<T: Into<Vec<u8>>>(
        self,
        secret_key: T,
    ) -> Result<MlKemBuilder<HasSecretKey>> {
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
/// ML-KEM builder with a complete key pair (public and secret keys)
pub type MlKemWithKeyPair = MlKemBuilder<HasKeyPair>;
/// ML-KEM builder with only the public key for encapsulation
pub type MlKemWithPublicKey = MlKemBuilder<HasPublicKey>;
/// ML-KEM builder with only the secret key for decapsulation
pub type MlKemWithSecretKey = MlKemBuilder<HasSecretKey>;
/// ML-KEM builder with ciphertext ready for decapsulation
pub type MlKemWithCiphertext = MlKemBuilder<HasCiphertext>;

// Public key access methods for HasKeyPair state
impl MlKemBuilder<HasKeyPair> {
    /// Get the public key bytes
    pub fn public_key(&self) -> &[u8] {
        self.public_key
            .as_ref()
            .expect("HasKeyPair must have public key")
    }

    /// Get the secret key bytes  
    pub fn secret_key(&self) -> &[u8] {
        self.secret_key
            .as_ref()
            .expect("HasKeyPair must have secret key")
    }

    /// Get the public key as a vector
    pub fn public_key_vec(&self) -> Vec<u8> {
        self.public_key
            .clone()
            .expect("HasKeyPair must have public key")
    }

    /// Get the secret key as a vector
    pub fn secret_key_vec(&self) -> Vec<u8> {
        self.secret_key
            .clone()
            .expect("HasKeyPair must have secret key")
    }
}

// Implementation for HasPublicKey state - can encapsulate
impl EncapsulateBuilder for MlKemBuilder<HasPublicKey> {
    fn encapsulate(self) -> impl AsyncEncapsulationResult {
        async move {
            let public_key = self
                .public_key
                .ok_or_else(|| CryptError::InternalError("Public key not set".to_string()))?;

            let (shared_secret_bytes, ciphertext) = match self.algorithm {
                KemAlgorithm::MlKem512 => {
                    use pqcrypto_mlkem::mlkem512::{encapsulate, PublicKey};
                    let pk = PublicKey::from_bytes(&public_key).map_err(|_| {
                        CryptError::InvalidKey("Invalid ML-KEM-512 public key".to_string())
                    })?;
                    let (ss, ct) = encapsulate(&pk);
                    (
                        PqSharedSecret::as_bytes(&ss).to_vec(),
                        PqCiphertext::as_bytes(&ct).to_vec(),
                    )
                }
                KemAlgorithm::MlKem768 => {
                    use pqcrypto_mlkem::mlkem768::{encapsulate, PublicKey};
                    let pk = PublicKey::from_bytes(&public_key).map_err(|_| {
                        CryptError::InvalidKey("Invalid ML-KEM-768 public key".to_string())
                    })?;
                    let (ss, ct) = encapsulate(&pk);
                    (
                        PqSharedSecret::as_bytes(&ss).to_vec(),
                        PqCiphertext::as_bytes(&ct).to_vec(),
                    )
                }
                KemAlgorithm::MlKem1024 => {
                    use pqcrypto_mlkem::mlkem1024::{encapsulate, PublicKey};
                    let pk = PublicKey::from_bytes(&public_key).map_err(|_| {
                        CryptError::InvalidKey("Invalid ML-KEM-1024 public key".to_string())
                    })?;
                    let (ss, ct) = encapsulate(&pk);
                    (
                        PqSharedSecret::as_bytes(&ss).to_vec(),
                        PqCiphertext::as_bytes(&ct).to_vec(),
                    )
                }
            };

            let shared_secret = SharedSecret::new(self.algorithm, shared_secret_bytes);
            Ok(EncapsulationResult::new(
                self.algorithm,
                ciphertext,
                shared_secret,
            ))
        }
    }
}

// Implementation for HasKeyPair state - can encapsulate or add ciphertext for decapsulation
impl EncapsulateBuilder for MlKemBuilder<HasKeyPair> {
    fn encapsulate(self) -> impl AsyncEncapsulationResult {
        async move {
            MlKemBuilder::<HasPublicKey> {
                algorithm: self.algorithm,
                state: PhantomData,
                public_key: self.public_key,
                secret_key: None,
                ciphertext: None,
            }
            .encapsulate()
            .await
        }
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
    fn decapsulate(self) -> impl AsyncDecapsulationResult {
        async move {
            let algorithm = self.algorithm;
            let secret_key = self.secret_key.ok_or_else(|| {
                CryptError::InvalidKey("Secret key required for decapsulation".to_string())
            })?;
            let ciphertext = self
                .ciphertext
                .ok_or_else(|| CryptError::InternalError("Ciphertext not set".to_string()))?;

            // Validate ciphertext size
            let expected_size = algorithm.ciphertext_size();
            if ciphertext.len() != expected_size {
                return Err(CryptError::InvalidKeySize {
                    expected: expected_size,
                    actual: ciphertext.len(),
                });
            }

            let shared_secret_bytes = match algorithm {
                KemAlgorithm::MlKem512 => {
                    use pqcrypto_mlkem::mlkem512::{decapsulate, Ciphertext, SecretKey};
                    let sk = SecretKey::from_bytes(&secret_key).map_err(|_| {
                        CryptError::InvalidKey("Invalid ML-KEM-512 secret key".to_string())
                    })?;
                    let ct = Ciphertext::from_bytes(&ciphertext).map_err(|_| {
                        CryptError::InvalidEncryptedData(
                            "Invalid ML-KEM-512 ciphertext".to_string(),
                        )
                    })?;
                    let ss = decapsulate(&ct, &sk);
                    PqSharedSecret::as_bytes(&ss).to_vec()
                }
                KemAlgorithm::MlKem768 => {
                    use pqcrypto_mlkem::mlkem768::{decapsulate, Ciphertext, SecretKey};
                    let sk = SecretKey::from_bytes(&secret_key).map_err(|_| {
                        CryptError::InvalidKey("Invalid ML-KEM-768 secret key".to_string())
                    })?;
                    let ct = Ciphertext::from_bytes(&ciphertext).map_err(|_| {
                        CryptError::InvalidEncryptedData(
                            "Invalid ML-KEM-768 ciphertext".to_string(),
                        )
                    })?;
                    let ss = decapsulate(&ct, &sk);
                    PqSharedSecret::as_bytes(&ss).to_vec()
                }
                KemAlgorithm::MlKem1024 => {
                    use pqcrypto_mlkem::mlkem1024::{decapsulate, Ciphertext, SecretKey};
                    let sk = SecretKey::from_bytes(&secret_key).map_err(|_| {
                        CryptError::InvalidKey("Invalid ML-KEM-1024 secret key".to_string())
                    })?;
                    let ct = Ciphertext::from_bytes(&ciphertext).map_err(|_| {
                        CryptError::InvalidEncryptedData(
                            "Invalid ML-KEM-1024 ciphertext".to_string(),
                        )
                    })?;
                    let ss = decapsulate(&ct, &sk);
                    PqSharedSecret::as_bytes(&ss).to_vec()
                }
            };

            let shared_secret = SharedSecret::new(algorithm, shared_secret_bytes);
            Ok(DecapsulationResult::new(algorithm, shared_secret))
        }
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
