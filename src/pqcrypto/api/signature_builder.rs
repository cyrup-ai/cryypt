//! Digital signature builder implementations

use crate::{CryptError, Result};
use super::{
    builder_traits::*,
    states::*,
};
use super::super::{
    SignatureAlgorithm, SignatureResult, VerificationResult,
};
use std::marker::PhantomData;

/// Main entry point for signature operations
pub struct SignatureBuilder;

impl SignatureBuilder {
    /// Create a new ML-DSA builder with the specified security level
    pub fn ml_dsa(security_level: u16) -> Result<MlDsaBuilder<NeedKeyPair>> {
        let algorithm = match security_level {
            44 | 2 => SignatureAlgorithm::MlDsa44,
            65 | 3 => SignatureAlgorithm::MlDsa65,
            87 | 5 => SignatureAlgorithm::MlDsa87,
            _ => return Err(CryptError::UnsupportedAlgorithm(
                format!("ML-DSA-{} is not supported. Use 44, 65, or 87", security_level)
            )),
        };
        
        Ok(MlDsaBuilder {
            algorithm,
            state: PhantomData,
            public_key: None,
            secret_key: None,
            message: None,
            signature: None,
        })
    }
    
    /// Create ML-DSA-44 builder (NIST security level 2)
    pub fn ml_dsa_44() -> MlDsaBuilder<NeedKeyPair> {
        MlDsaBuilder {
            algorithm: SignatureAlgorithm::MlDsa44,
            state: PhantomData,
            public_key: None,
            secret_key: None,
            message: None,
            signature: None,
        }
    }
    
    /// Create ML-DSA-65 builder (NIST security level 3)
    pub fn ml_dsa_65() -> MlDsaBuilder<NeedKeyPair> {
        MlDsaBuilder {
            algorithm: SignatureAlgorithm::MlDsa65,
            state: PhantomData,
            public_key: None,
            secret_key: None,
            message: None,
            signature: None,
        }
    }
    
    /// Create ML-DSA-87 builder (NIST security level 5)
    pub fn ml_dsa_87() -> MlDsaBuilder<NeedKeyPair> {
        MlDsaBuilder {
            algorithm: SignatureAlgorithm::MlDsa87,
            state: PhantomData,
            public_key: None,
            secret_key: None,
            message: None,
            signature: None,
        }
    }
    
    /// Create a new FALCON builder with the specified security level
    pub fn falcon(security_level: u16) -> Result<FalconBuilder<NeedKeyPair>> {
        let algorithm = match security_level {
            512 | 1 => SignatureAlgorithm::Falcon512,
            1024 | 5 => SignatureAlgorithm::Falcon1024,
            _ => return Err(CryptError::UnsupportedAlgorithm(
                format!("FALCON-{} is not supported. Use 512 or 1024", security_level)
            )),
        };
        
        Ok(FalconBuilder {
            algorithm,
            state: PhantomData,
            public_key: None,
            secret_key: None,
            message: None,
            signature: None,
        })
    }
    
    /// Create FALCON-512 builder (NIST security level 1)
    pub fn falcon_512() -> FalconBuilder<NeedKeyPair> {
        FalconBuilder {
            algorithm: SignatureAlgorithm::Falcon512,
            state: PhantomData,
            public_key: None,
            secret_key: None,
            message: None,
            signature: None,
        }
    }
    
    /// Create FALCON-1024 builder (NIST security level 5)
    pub fn falcon_1024() -> FalconBuilder<NeedKeyPair> {
        FalconBuilder {
            algorithm: SignatureAlgorithm::Falcon1024,
            state: PhantomData,
            public_key: None,
            secret_key: None,
            message: None,
            signature: None,
        }
    }
    
    /// Create a new SPHINCS+ builder
    pub fn sphincs_plus(variant: &str) -> Result<SphincsBuilder<NeedKeyPair>> {
        let algorithm = match variant {
            "sha256-128f-simple" => SignatureAlgorithm::SphincsShaSha256_128fSimple,
            "sha256-128s-simple" => SignatureAlgorithm::SphincsShaSha256_128sSimple,
            "sha256-192f-simple" => SignatureAlgorithm::SphincsShaSha256_192fSimple,
            "sha256-192s-simple" => SignatureAlgorithm::SphincsShaSha256_192sSimple,
            "sha256-256f-simple" => SignatureAlgorithm::SphincsShaSha256_256fSimple,
            "sha256-256s-simple" => SignatureAlgorithm::SphincsShaSha256_256sSimple,
            _ => return Err(CryptError::UnsupportedAlgorithm(
                format!("SPHINCS+-{} is not supported", variant)
            )),
        };
        
        Ok(SphincsBuilder {
            algorithm,
            state: PhantomData,
            public_key: None,
            secret_key: None,
            message: None,
            signature: None,
        })
    }
}

/// Base trait for signature builders
trait BaseSignatureBuilder {
    fn algorithm(&self) -> SignatureAlgorithm;
    fn validate_public_key(&self, key: &[u8]) -> Result<()> {
        let expected = self.algorithm().public_key_size();
        if key.len() != expected {
            return Err(CryptError::InvalidKeySize {
                expected,
                actual: key.len(),
            });
        }
        Ok(())
    }
    
    fn validate_secret_key(&self, key: &[u8]) -> Result<()> {
        let expected = self.algorithm().secret_key_size();
        if key.len() != expected {
            return Err(CryptError::InvalidKeySize {
                expected,
                actual: key.len(),
            });
        }
        Ok(())
    }
}

/// ML-DSA builder type
pub struct MlDsaBuilder<State> {
    algorithm: SignatureAlgorithm,
    state: PhantomData<State>,
    public_key: Option<Vec<u8>>,
    secret_key: Option<Vec<u8>>,
    message: Option<Vec<u8>>,
    signature: Option<Vec<u8>>,
}

impl<State> BaseSignatureBuilder for MlDsaBuilder<State> {
    fn algorithm(&self) -> SignatureAlgorithm {
        self.algorithm
    }
}

/// FALCON builder type
pub struct FalconBuilder<State> {
    algorithm: SignatureAlgorithm,
    state: PhantomData<State>,
    public_key: Option<Vec<u8>>,
    secret_key: Option<Vec<u8>>,
    message: Option<Vec<u8>>,
    signature: Option<Vec<u8>>,
}

impl<State> BaseSignatureBuilder for FalconBuilder<State> {
    fn algorithm(&self) -> SignatureAlgorithm {
        self.algorithm
    }
}

/// SPHINCS+ builder type
pub struct SphincsBuilder<State> {
    algorithm: SignatureAlgorithm,
    state: PhantomData<State>,
    public_key: Option<Vec<u8>>,
    secret_key: Option<Vec<u8>>,
    message: Option<Vec<u8>>,
    signature: Option<Vec<u8>>,
}

impl<State> BaseSignatureBuilder for SphincsBuilder<State> {
    fn algorithm(&self) -> SignatureAlgorithm {
        self.algorithm
    }
}

// ML-DSA implementations
impl SignatureKeyPairBuilder for MlDsaBuilder<NeedKeyPair> {
    type Output = MlDsaBuilder<HasKeyPair>;
    
    async fn generate(self) -> Result<Self::Output> {
        let (pk, sk) = match self.algorithm {
            SignatureAlgorithm::MlDsa44 => {
                let (pk, sk) = pqcrypto_mldsa::mldsa44::keypair();
                (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
            }
            SignatureAlgorithm::MlDsa65 => {
                let (pk, sk) = pqcrypto_mldsa::mldsa65::keypair();
                (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
            }
            SignatureAlgorithm::MlDsa87 => {
                let (pk, sk) = pqcrypto_mldsa::mldsa87::keypair();
                (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
            }
            _ => return Err(CryptError::InternalError("Invalid algorithm for ML-DSA".to_string())),
        };
        
        Ok(MlDsaBuilder {
            algorithm: self.algorithm,
            state: PhantomData,
            public_key: Some(pk),
            secret_key: Some(sk),
            message: None,
            signature: None,
        })
    }
    
    fn with_keypair<T: Into<Vec<u8>>>(self, public_key: T, secret_key: T) -> Result<Self::Output> {
        let pk = public_key.into();
        let sk = secret_key.into();
        
        self.validate_public_key(&pk)?;
        self.validate_secret_key(&sk)?;
        
        Ok(MlDsaBuilder {
            algorithm: self.algorithm,
            state: PhantomData,
            public_key: Some(pk),
            secret_key: Some(sk),
            message: None,
            signature: None,
        })
    }
    
    fn with_public_key<T: Into<Vec<u8>>>(self, public_key: T) -> Result<MlDsaBuilder<HasPublicKey>> {
        let pk = public_key.into();
        self.validate_public_key(&pk)?;
        
        Ok(MlDsaBuilder {
            algorithm: self.algorithm,
            state: PhantomData,
            public_key: Some(pk),
            secret_key: None,
            message: None,
            signature: None,
        })
    }
    
    fn with_secret_key<T: Into<Vec<u8>>>(self, secret_key: T) -> Result<MlDsaBuilder<HasSecretKey>> {
        let sk = secret_key.into();
        self.validate_secret_key(&sk)?;
        
        Ok(MlDsaBuilder {
            algorithm: self.algorithm,
            state: PhantomData,
            public_key: None,
            secret_key: Some(sk),
            message: None,
            signature: None,
        })
    }
}

// Type aliases for ML-DSA
pub type MlDsaWithKeyPair = MlDsaBuilder<HasKeyPair>;
pub type MlDsaWithSecretKey = MlDsaBuilder<HasSecretKey>;
pub type MlDsaWithPublicKey = MlDsaBuilder<HasPublicKey>;
pub type MlDsaWithMessage = MlDsaBuilder<HasMessage>;
pub type MlDsaWithSignature = MlDsaBuilder<HasSignature>;

// FALCON implementations
impl SignatureKeyPairBuilder for FalconBuilder<NeedKeyPair> {
    type Output = FalconBuilder<HasKeyPair>;
    
    async fn generate(self) -> Result<Self::Output> {
        let (pk, sk) = match self.algorithm {
            SignatureAlgorithm::Falcon512 => {
                let (pk, sk) = pqcrypto_falcon::falcon512::keypair();
                (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
            }
            SignatureAlgorithm::Falcon1024 => {
                let (pk, sk) = pqcrypto_falcon::falcon1024::keypair();
                (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
            }
            _ => return Err(CryptError::InternalError("Invalid algorithm for FALCON".to_string())),
        };
        
        Ok(FalconBuilder {
            algorithm: self.algorithm,
            state: PhantomData,
            public_key: Some(pk),
            secret_key: Some(sk),
            message: None,
            signature: None,
        })
    }
    
    fn with_keypair<T: Into<Vec<u8>>>(self, public_key: T, secret_key: T) -> Result<Self::Output> {
        let pk = public_key.into();
        let sk = secret_key.into();
        
        self.validate_public_key(&pk)?;
        self.validate_secret_key(&sk)?;
        
        Ok(FalconBuilder {
            algorithm: self.algorithm,
            state: PhantomData,
            public_key: Some(pk),
            secret_key: Some(sk),
            message: None,
            signature: None,
        })
    }
    
    fn with_public_key<T: Into<Vec<u8>>>(self, public_key: T) -> Result<FalconBuilder<HasPublicKey>> {
        let pk = public_key.into();
        self.validate_public_key(&pk)?;
        
        Ok(FalconBuilder {
            algorithm: self.algorithm,
            state: PhantomData,
            public_key: Some(pk),
            secret_key: None,
            message: None,
            signature: None,
        })
    }
    
    fn with_secret_key<T: Into<Vec<u8>>>(self, secret_key: T) -> Result<FalconBuilder<HasSecretKey>> {
        let sk = secret_key.into();
        self.validate_secret_key(&sk)?;
        
        Ok(FalconBuilder {
            algorithm: self.algorithm,
            state: PhantomData,
            public_key: None,
            secret_key: Some(sk),
            message: None,
            signature: None,
        })
    }
}

// Type aliases for FALCON
pub type FalconWithKeyPair = FalconBuilder<HasKeyPair>;
pub type FalconWithSecretKey = FalconBuilder<HasSecretKey>;
pub type FalconWithPublicKey = FalconBuilder<HasPublicKey>;
pub type FalconWithMessage = FalconBuilder<HasMessage>;
pub type FalconWithSignature = FalconBuilder<HasSignature>;

// SPHINCS+ implementations
impl SignatureKeyPairBuilder for SphincsBuilder<NeedKeyPair> {
    type Output = SphincsBuilder<HasKeyPair>;
    
    async fn generate(self) -> Result<Self::Output> {
        let (pk, sk) = match self.algorithm {
            SignatureAlgorithm::SphincsShaSha256_128fSimple => {
                let (pk, sk) = pqcrypto_sphincsplus::sphincssha256128fsimple::keypair();
                (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
            }
            SignatureAlgorithm::SphincsShaSha256_128sSimple => {
                let (pk, sk) = pqcrypto_sphincsplus::sphincssha256128ssimple::keypair();
                (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
            }
            SignatureAlgorithm::SphincsShaSha256_192fSimple => {
                let (pk, sk) = pqcrypto_sphincsplus::sphincssha256192fsimple::keypair();
                (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
            }
            SignatureAlgorithm::SphincsShaSha256_192sSimple => {
                let (pk, sk) = pqcrypto_sphincsplus::sphincssha256192ssimple::keypair();
                (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
            }
            SignatureAlgorithm::SphincsShaSha256_256fSimple => {
                let (pk, sk) = pqcrypto_sphincsplus::sphincssha256256fsimple::keypair();
                (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
            }
            SignatureAlgorithm::SphincsShaSha256_256sSimple => {
                let (pk, sk) = pqcrypto_sphincsplus::sphincssha256256ssimple::keypair();
                (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
            }
            _ => return Err(CryptError::InternalError("Invalid algorithm for SPHINCS+".to_string())),
        };
        
        Ok(SphincsBuilder {
            algorithm: self.algorithm,
            state: PhantomData,
            public_key: Some(pk),
            secret_key: Some(sk),
            message: None,
            signature: None,
        })
    }
    
    fn with_keypair<T: Into<Vec<u8>>>(self, public_key: T, secret_key: T) -> Result<Self::Output> {
        let pk = public_key.into();
        let sk = secret_key.into();
        
        self.validate_public_key(&pk)?;
        self.validate_secret_key(&sk)?;
        
        Ok(SphincsBuilder {
            algorithm: self.algorithm,
            state: PhantomData,
            public_key: Some(pk),
            secret_key: Some(sk),
            message: None,
            signature: None,
        })
    }
    
    fn with_public_key<T: Into<Vec<u8>>>(self, public_key: T) -> Result<SphincsBuilder<HasPublicKey>> {
        let pk = public_key.into();
        self.validate_public_key(&pk)?;
        
        Ok(SphincsBuilder {
            algorithm: self.algorithm,
            state: PhantomData,
            public_key: Some(pk),
            secret_key: None,
            message: None,
            signature: None,
        })
    }
    
    fn with_secret_key<T: Into<Vec<u8>>>(self, secret_key: T) -> Result<SphincsBuilder<HasSecretKey>> {
        let sk = secret_key.into();
        self.validate_secret_key(&sk)?;
        
        Ok(SphincsBuilder {
            algorithm: self.algorithm,
            state: PhantomData,
            public_key: None,
            secret_key: Some(sk),
            message: None,
            signature: None,
        })
    }
}

// Type aliases for SPHINCS+
pub type SphincsWithKeyPair = SphincsBuilder<HasKeyPair>;
pub type SphincsWithSecretKey = SphincsBuilder<HasSecretKey>;
pub type SphincsWithPublicKey = SphincsBuilder<HasPublicKey>;
pub type SphincsWithMessage = SphincsBuilder<HasMessage>;
pub type SphincsWithSignature = SphincsBuilder<HasSignature>;

// Message builder implementations for ML-DSA
impl<State> MessageBuilder for MlDsaBuilder<State> {
    type Output = MlDsaBuilder<HasMessage>;
    
    fn with_message<T: Into<Vec<u8>>>(self, message: T) -> Self::Output {
        MlDsaBuilder {
            algorithm: self.algorithm,
            state: PhantomData,
            public_key: self.public_key,
            secret_key: self.secret_key,
            message: Some(message.into()),
            signature: self.signature,
        }
    }
}

// Message builder implementations for FALCON
impl<State> MessageBuilder for FalconBuilder<State> {
    type Output = FalconBuilder<HasMessage>;
    
    fn with_message<T: Into<Vec<u8>>>(self, message: T) -> Self::Output {
        FalconBuilder {
            algorithm: self.algorithm,
            state: PhantomData,
            public_key: self.public_key,
            secret_key: self.secret_key,
            message: Some(message.into()),
            signature: self.signature,
        }
    }
}

// Message builder implementations for SPHINCS+
impl<State> MessageBuilder for SphincsBuilder<State> {
    type Output = SphincsBuilder<HasMessage>;
    
    fn with_message<T: Into<Vec<u8>>>(self, message: T) -> Self::Output {
        SphincsBuilder {
            algorithm: self.algorithm,
            state: PhantomData,
            public_key: self.public_key,
            secret_key: self.secret_key,
            message: Some(message.into()),
            signature: self.signature,
        }
    }
}

// Signature data builder implementations for ML-DSA
impl<State> SignatureDataBuilder for MlDsaBuilder<State> {
    type Output = MlDsaBuilder<HasSignature>;
    
    fn with_signature<T: Into<Vec<u8>>>(self, signature: T) -> Self::Output {
        MlDsaBuilder {
            algorithm: self.algorithm,
            state: PhantomData,
            public_key: self.public_key,
            secret_key: self.secret_key,
            message: self.message,
            signature: Some(signature.into()),
        }
    }
}

// Signature data builder implementations for FALCON
impl<State> SignatureDataBuilder for FalconBuilder<State> {
    type Output = FalconBuilder<HasSignature>;
    
    fn with_signature<T: Into<Vec<u8>>>(self, signature: T) -> Self::Output {
        FalconBuilder {
            algorithm: self.algorithm,
            state: PhantomData,
            public_key: self.public_key,
            secret_key: self.secret_key,
            message: self.message,
            signature: Some(signature.into()),
        }
    }
}

// Signature data builder implementations for SPHINCS+
impl<State> SignatureDataBuilder for SphincsBuilder<State> {
    type Output = SphincsBuilder<HasSignature>;
    
    fn with_signature<T: Into<Vec<u8>>>(self, signature: T) -> Self::Output {
        SphincsBuilder {
            algorithm: self.algorithm,
            state: PhantomData,
            public_key: self.public_key,
            secret_key: self.secret_key,
            message: self.message,
            signature: Some(signature.into()),
        }
    }
}

// Sign builder implementation for ML-DSA with message
impl SignBuilder for MlDsaBuilder<HasMessage> {
    async fn sign(self) -> Result<SignatureResult> {
        let secret_key = self.secret_key
            .ok_or_else(|| CryptError::InvalidKey("Secret key required for signing".to_string()))?;
        let message = self.message
            .ok_or_else(|| CryptError::InternalError("Message not set".to_string()))?;
        
        let signature = match self.algorithm {
            SignatureAlgorithm::MlDsa44 => {
                use pqcrypto_mldsa::mldsa44::{SecretKey, sign};
                let sk = SecretKey::from_bytes(&secret_key)
                    .map_err(|_| CryptError::InvalidKey("Invalid ML-DSA-44 secret key".to_string()))?;
                let sig = sign(&message, &sk);
                sig.as_bytes().to_vec()
            }
            SignatureAlgorithm::MlDsa65 => {
                use pqcrypto_mldsa::mldsa65::{SecretKey, sign};
                let sk = SecretKey::from_bytes(&secret_key)
                    .map_err(|_| CryptError::InvalidKey("Invalid ML-DSA-65 secret key".to_string()))?;
                let sig = sign(&message, &sk);
                sig.as_bytes().to_vec()
            }
            SignatureAlgorithm::MlDsa87 => {
                use pqcrypto_mldsa::mldsa87::{SecretKey, sign};
                let sk = SecretKey::from_bytes(&secret_key)
                    .map_err(|_| CryptError::InvalidKey("Invalid ML-DSA-87 secret key".to_string()))?;
                let sig = sign(&message, &sk);
                sig.as_bytes().to_vec()
            }
            _ => return Err(CryptError::InternalError("Invalid algorithm for ML-DSA".to_string())),
        };
        
        Ok(SignatureResult::new(self.algorithm, signature, None))
    }
}

// Sign builder implementation for FALCON with message
impl SignBuilder for FalconBuilder<HasMessage> {
    async fn sign(self) -> Result<SignatureResult> {
        let secret_key = self.secret_key
            .ok_or_else(|| CryptError::InvalidKey("Secret key required for signing".to_string()))?;
        let message = self.message
            .ok_or_else(|| CryptError::InternalError("Message not set".to_string()))?;
        
        let signature = match self.algorithm {
            SignatureAlgorithm::Falcon512 => {
                use pqcrypto_falcon::falcon512::{SecretKey, sign};
                let sk = SecretKey::from_bytes(&secret_key)
                    .map_err(|_| CryptError::InvalidKey("Invalid FALCON-512 secret key".to_string()))?;
                let sig = sign(&message, &sk);
                sig.as_bytes().to_vec()
            }
            SignatureAlgorithm::Falcon1024 => {
                use pqcrypto_falcon::falcon1024::{SecretKey, sign};
                let sk = SecretKey::from_bytes(&secret_key)
                    .map_err(|_| CryptError::InvalidKey("Invalid FALCON-1024 secret key".to_string()))?;
                let sig = sign(&message, &sk);
                sig.as_bytes().to_vec()
            }
            _ => return Err(CryptError::InternalError("Invalid algorithm for FALCON".to_string())),
        };
        
        Ok(SignatureResult::new(self.algorithm, signature, None))
    }
}

// Sign builder implementation for SPHINCS+ with message
impl SignBuilder for SphincsBuilder<HasMessage> {
    async fn sign(self) -> Result<SignatureResult> {
        let secret_key = self.secret_key
            .ok_or_else(|| CryptError::InvalidKey("Secret key required for signing".to_string()))?;
        let message = self.message
            .ok_or_else(|| CryptError::InternalError("Message not set".to_string()))?;
        
        let signature = match self.algorithm {
            SignatureAlgorithm::SphincsShaSha256_128fSimple => {
                use pqcrypto_sphincsplus::sphincssha256128fsimple::{SecretKey, sign};
                let sk = SecretKey::from_bytes(&secret_key)
                    .map_err(|_| CryptError::InvalidKey("Invalid SPHINCS+ secret key".to_string()))?;
                let sig = sign(&message, &sk);
                sig.as_bytes().to_vec()
            }
            SignatureAlgorithm::SphincsShaSha256_128sSimple => {
                use pqcrypto_sphincsplus::sphincssha256128ssimple::{SecretKey, sign};
                let sk = SecretKey::from_bytes(&secret_key)
                    .map_err(|_| CryptError::InvalidKey("Invalid SPHINCS+ secret key".to_string()))?;
                let sig = sign(&message, &sk);
                sig.as_bytes().to_vec()
            }
            SignatureAlgorithm::SphincsShaSha256_192fSimple => {
                use pqcrypto_sphincsplus::sphincssha256192fsimple::{SecretKey, sign};
                let sk = SecretKey::from_bytes(&secret_key)
                    .map_err(|_| CryptError::InvalidKey("Invalid SPHINCS+ secret key".to_string()))?;
                let sig = sign(&message, &sk);
                sig.as_bytes().to_vec()
            }
            SignatureAlgorithm::SphincsShaSha256_192sSimple => {
                use pqcrypto_sphincsplus::sphincssha256192ssimple::{SecretKey, sign};
                let sk = SecretKey::from_bytes(&secret_key)
                    .map_err(|_| CryptError::InvalidKey("Invalid SPHINCS+ secret key".to_string()))?;
                let sig = sign(&message, &sk);
                sig.as_bytes().to_vec()
            }
            SignatureAlgorithm::SphincsShaSha256_256fSimple => {
                use pqcrypto_sphincsplus::sphincssha256256fsimple::{SecretKey, sign};
                let sk = SecretKey::from_bytes(&secret_key)
                    .map_err(|_| CryptError::InvalidKey("Invalid SPHINCS+ secret key".to_string()))?;
                let sig = sign(&message, &sk);
                sig.as_bytes().to_vec()
            }
            SignatureAlgorithm::SphincsShaSha256_256sSimple => {
                use pqcrypto_sphincsplus::sphincssha256256ssimple::{SecretKey, sign};
                let sk = SecretKey::from_bytes(&secret_key)
                    .map_err(|_| CryptError::InvalidKey("Invalid SPHINCS+ secret key".to_string()))?;
                let sig = sign(&message, &sk);
                sig.as_bytes().to_vec()
            }
            _ => return Err(CryptError::InternalError("Invalid algorithm for SPHINCS+".to_string())),
        };
        
        Ok(SignatureResult::new(self.algorithm, signature, None))
    }
}

// Verify builder implementation for ML-DSA with signature
impl VerifyBuilder for MlDsaBuilder<HasSignature> {
    async fn verify(self) -> Result<VerificationResult> {
        let public_key = self.public_key
            .ok_or_else(|| CryptError::InvalidKey("Public key required for verification".to_string()))?;
        let message = self.message
            .ok_or_else(|| CryptError::InvalidParameters("Message required for verification".to_string()))?;
        let signature = self.signature
            .ok_or_else(|| CryptError::InternalError("Signature not set".to_string()))?;
        
        let is_valid = match self.algorithm {
            SignatureAlgorithm::MlDsa44 => {
                use pqcrypto_mldsa::mldsa44::{PublicKey, Signature, verify};
                let pk = PublicKey::from_bytes(&public_key)
                    .map_err(|_| CryptError::InvalidKey("Invalid ML-DSA-44 public key".to_string()))?;
                let sig = Signature::from_bytes(&signature)
                    .map_err(|_| CryptError::InvalidParameters("Invalid ML-DSA-44 signature".to_string()))?;
                verify(&sig, &message, &pk).is_ok()
            }
            SignatureAlgorithm::MlDsa65 => {
                use pqcrypto_mldsa::mldsa65::{PublicKey, Signature, verify};
                let pk = PublicKey::from_bytes(&public_key)
                    .map_err(|_| CryptError::InvalidKey("Invalid ML-DSA-65 public key".to_string()))?;
                let sig = Signature::from_bytes(&signature)
                    .map_err(|_| CryptError::InvalidParameters("Invalid ML-DSA-65 signature".to_string()))?;
                verify(&sig, &message, &pk).is_ok()
            }
            SignatureAlgorithm::MlDsa87 => {
                use pqcrypto_mldsa::mldsa87::{PublicKey, Signature, verify};
                let pk = PublicKey::from_bytes(&public_key)
                    .map_err(|_| CryptError::InvalidKey("Invalid ML-DSA-87 public key".to_string()))?;
                let sig = Signature::from_bytes(&signature)
                    .map_err(|_| CryptError::InvalidParameters("Invalid ML-DSA-87 signature".to_string()))?;
                verify(&sig, &message, &pk).is_ok()
            }
            _ => return Err(CryptError::InternalError("Invalid algorithm for ML-DSA".to_string())),
        };
        
        Ok(VerificationResult::new(self.algorithm, is_valid, None))
    }
}

// Verify builder implementation for FALCON with signature
impl VerifyBuilder for FalconBuilder<HasSignature> {
    async fn verify(self) -> Result<VerificationResult> {
        let public_key = self.public_key
            .ok_or_else(|| CryptError::InvalidKey("Public key required for verification".to_string()))?;
        let message = self.message
            .ok_or_else(|| CryptError::InvalidParameters("Message required for verification".to_string()))?;
        let signature = self.signature
            .ok_or_else(|| CryptError::InternalError("Signature not set".to_string()))?;
        
        let is_valid = match self.algorithm {
            SignatureAlgorithm::Falcon512 => {
                use pqcrypto_falcon::falcon512::{PublicKey, Signature, verify};
                let pk = PublicKey::from_bytes(&public_key)
                    .map_err(|_| CryptError::InvalidKey("Invalid FALCON-512 public key".to_string()))?;
                let sig = Signature::from_bytes(&signature)
                    .map_err(|_| CryptError::InvalidParameters("Invalid FALCON-512 signature".to_string()))?;
                verify(&sig, &message, &pk).is_ok()
            }
            SignatureAlgorithm::Falcon1024 => {
                use pqcrypto_falcon::falcon1024::{PublicKey, Signature, verify};
                let pk = PublicKey::from_bytes(&public_key)
                    .map_err(|_| CryptError::InvalidKey("Invalid FALCON-1024 public key".to_string()))?;
                let sig = Signature::from_bytes(&signature)
                    .map_err(|_| CryptError::InvalidParameters("Invalid FALCON-1024 signature".to_string()))?;
                verify(&sig, &message, &pk).is_ok()
            }
            _ => return Err(CryptError::InternalError("Invalid algorithm for FALCON".to_string())),
        };
        
        Ok(VerificationResult::new(self.algorithm, is_valid, None))
    }
}

// Verify builder implementation for SPHINCS+ with signature
impl VerifyBuilder for SphincsBuilder<HasSignature> {
    async fn verify(self) -> Result<VerificationResult> {
        let public_key = self.public_key
            .ok_or_else(|| CryptError::InvalidKey("Public key required for verification".to_string()))?;
        let message = self.message
            .ok_or_else(|| CryptError::InvalidParameters("Message required for verification".to_string()))?;
        let signature = self.signature
            .ok_or_else(|| CryptError::InternalError("Signature not set".to_string()))?;
        
        let is_valid = match self.algorithm {
            SignatureAlgorithm::SphincsShaSha256_128fSimple => {
                use pqcrypto_sphincsplus::sphincssha256128fsimple::{PublicKey, Signature, verify};
                let pk = PublicKey::from_bytes(&public_key)
                    .map_err(|_| CryptError::InvalidKey("Invalid SPHINCS+ public key".to_string()))?;
                let sig = Signature::from_bytes(&signature)
                    .map_err(|_| CryptError::InvalidParameters("Invalid SPHINCS+ signature".to_string()))?;
                verify(&sig, &message, &pk).is_ok()
            }
            SignatureAlgorithm::SphincsShaSha256_128sSimple => {
                use pqcrypto_sphincsplus::sphincssha256128ssimple::{PublicKey, Signature, verify};
                let pk = PublicKey::from_bytes(&public_key)
                    .map_err(|_| CryptError::InvalidKey("Invalid SPHINCS+ public key".to_string()))?;
                let sig = Signature::from_bytes(&signature)
                    .map_err(|_| CryptError::InvalidParameters("Invalid SPHINCS+ signature".to_string()))?;
                verify(&sig, &message, &pk).is_ok()
            }
            SignatureAlgorithm::SphincsShaSha256_192fSimple => {
                use pqcrypto_sphincsplus::sphincssha256192fsimple::{PublicKey, Signature, verify};
                let pk = PublicKey::from_bytes(&public_key)
                    .map_err(|_| CryptError::InvalidKey("Invalid SPHINCS+ public key".to_string()))?;
                let sig = Signature::from_bytes(&signature)
                    .map_err(|_| CryptError::InvalidParameters("Invalid SPHINCS+ signature".to_string()))?;
                verify(&sig, &message, &pk).is_ok()
            }
            SignatureAlgorithm::SphincsShaSha256_192sSimple => {
                use pqcrypto_sphincsplus::sphincssha256192ssimple::{PublicKey, Signature, verify};
                let pk = PublicKey::from_bytes(&public_key)
                    .map_err(|_| CryptError::InvalidKey("Invalid SPHINCS+ public key".to_string()))?;
                let sig = Signature::from_bytes(&signature)
                    .map_err(|_| CryptError::InvalidParameters("Invalid SPHINCS+ signature".to_string()))?;
                verify(&sig, &message, &pk).is_ok()
            }
            SignatureAlgorithm::SphincsShaSha256_256fSimple => {
                use pqcrypto_sphincsplus::sphincssha256256fsimple::{PublicKey, Signature, verify};
                let pk = PublicKey::from_bytes(&public_key)
                    .map_err(|_| CryptError::InvalidKey("Invalid SPHINCS+ public key".to_string()))?;
                let sig = Signature::from_bytes(&signature)
                    .map_err(|_| CryptError::InvalidParameters("Invalid SPHINCS+ signature".to_string()))?;
                verify(&sig, &message, &pk).is_ok()
            }
            SignatureAlgorithm::SphincsShaSha256_256sSimple => {
                use pqcrypto_sphincsplus::sphincssha256256ssimple::{PublicKey, Signature, verify};
                let pk = PublicKey::from_bytes(&public_key)
                    .map_err(|_| CryptError::InvalidKey("Invalid SPHINCS+ public key".to_string()))?;
                let sig = Signature::from_bytes(&signature)
                    .map_err(|_| CryptError::InvalidParameters("Invalid SPHINCS+ signature".to_string()))?;
                verify(&sig, &message, &pk).is_ok()
            }
            _ => return Err(CryptError::InternalError("Invalid algorithm for SPHINCS+".to_string())),
        };
        
        Ok(VerificationResult::new(self.algorithm, is_valid, None))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_signature_builder_creation() {
        // Test ML-DSA
        assert!(SignatureBuilder::ml_dsa(44).is_ok());
        assert!(SignatureBuilder::ml_dsa(65).is_ok());
        assert!(SignatureBuilder::ml_dsa(87).is_ok());
        assert!(SignatureBuilder::ml_dsa(100).is_err());
        
        // Test FALCON
        assert!(SignatureBuilder::falcon(512).is_ok());
        assert!(SignatureBuilder::falcon(1024).is_ok());
        assert!(SignatureBuilder::falcon(2048).is_err());
        
        // Test SPHINCS+
        assert!(SignatureBuilder::sphincs_plus("sha256-128f-simple").is_ok());
        assert!(SignatureBuilder::sphincs_plus("invalid-variant").is_err());
    }
}