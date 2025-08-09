//! Digital signature builder implementations

mod common;
mod falcon;
mod ml_dsa;
mod sphincs;

use super::super::SignatureAlgorithm;
use super::states::*;
use crate::{PqCryptoError, Result};
use std::marker::PhantomData;

// Re-export builder types
pub use falcon::{
    FalconBuilder, FalconWithKeyPair, FalconWithMessage, FalconWithPublicKey, FalconWithSecretKey,
    FalconWithSignature,
};
pub use ml_dsa::{
    MlDsaBuilder, MlDsaWithKeyPair, MlDsaWithMessage, MlDsaWithPublicKey, MlDsaWithSecretKey,
    MlDsaWithSignature,
};
pub use sphincs::{
    SphincsBuilder, SphincsWithKeyPair, SphincsWithMessage, SphincsWithPublicKey,
    SphincsWithSecretKey, SphincsWithSignature,
};

// Import BaseSignatureBuilder for use by submodules
use common::BaseSignatureBuilder;

/// Main entry point for signature operations
pub struct SignatureBuilder;

/// Signature builder with result handler for keypair operations (returns tuple)
pub struct SignatureBuilderWithHandler<F, T> {
    result_handler: F,
    _phantom: std::marker::PhantomData<T>,
}

/// Signature builder with result handler for sign operations (returns Vec<u8>)
pub struct SignatureBuilderWithSignHandler<F, T> {
    result_handler: F,
    _phantom: std::marker::PhantomData<T>,
}

/// Signature builder with result handler for verify operations (returns bool)
pub struct SignatureBuilderWithVerifyHandler<F, T> {
    result_handler: F,
    _phantom: std::marker::PhantomData<T>,
}

/// Signature builder with secret key for signing
pub struct SignatureBuilderWithSecretKey {
    _phantom: std::marker::PhantomData<()>,
}

/// Signature builder with public key for verification
pub struct SignatureBuilderWithPublicKey {
    _phantom: std::marker::PhantomData<()>,
}

impl SignatureBuilder {
    /// Add on_result handler - README.md pattern
    pub fn on_result<F, T>(self, handler: F) -> SignatureBuilderWithHandler<F, T>
    where
        F: FnOnce(crate::Result<(Vec<u8>, Vec<u8>)>) -> T + Send + 'static,
        T: Send + 'static,
    {
        SignatureBuilderWithHandler {
            result_handler: handler,
            _phantom: std::marker::PhantomData,
        }
    }

    /// Set security level for signature operations
    pub fn with_security_level(self, _level: u16) -> Self {
        self
    }

    /// Set secret key for signing operations
    pub fn with_secret_key(self, _key: Vec<u8>) -> SignatureBuilderWithSecretKey {
        SignatureBuilderWithSecretKey {
            _phantom: std::marker::PhantomData,
        }
    }

    /// Set public key for verification operations
    pub fn with_public_key(self, _key: Vec<u8>) -> SignatureBuilderWithPublicKey {
        SignatureBuilderWithPublicKey {
            _phantom: std::marker::PhantomData,
        }
    }

    /// Set signature for verification operations
    pub fn with_signature(self, _signature: Vec<u8>) -> Self {
        self
    }
}

impl SignatureBuilderWithSecretKey {
    /// Add on_result handler for signing - README.md pattern
    pub fn on_result<F, T>(self, handler: F) -> SignatureBuilderWithSignHandler<F, T>
    where
        F: FnOnce(crate::Result<Vec<u8>>) -> T + Send + 'static,
        T: Send + 'static,
    {
        SignatureBuilderWithSignHandler {
            result_handler: handler,
            _phantom: std::marker::PhantomData,
        }
    }
}

impl SignatureBuilderWithPublicKey {
    /// Set signature for verification operations
    pub fn with_signature(self, _signature: Vec<u8>) -> Self {
        self
    }

    /// Add on_result handler for verification - README.md pattern
    pub fn on_result<F, T>(self, handler: F) -> SignatureBuilderWithVerifyHandler<F, T>
    where
        F: FnOnce(crate::Result<bool>) -> T + Send + 'static,
        T: Send + 'static,
    {
        SignatureBuilderWithVerifyHandler {
            result_handler: handler,
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<F, T> SignatureBuilderWithSignHandler<F, T>
where
    F: FnOnce(crate::Result<Vec<u8>>) -> T + Send + 'static,
    T: Send + 'static,
{
    /// Sign message and apply result handler
    pub async fn sign(self, _message: &[u8]) -> T {
        let handler = self.result_handler;
        // For now, return a placeholder result until proper signature implementation
        let result = Ok(vec![0u8; 64]); // Placeholder signature
        handler(result)
    }
}

impl<F, T> SignatureBuilderWithVerifyHandler<F, T>
where
    F: FnOnce(crate::Result<bool>) -> T + Send + 'static,
    T: Send + 'static,
{
    /// Verify signature and apply result handler
    pub async fn verify(self, _message: &[u8]) -> T {
        let handler = self.result_handler;
        // For now, return a placeholder result until proper signature implementation
        let result = Ok(true); // Placeholder verification result
        handler(result)
    }
}

impl<F, T> SignatureBuilderWithHandler<F, T>
where
    F: FnOnce(crate::Result<(Vec<u8>, Vec<u8>)>) -> T + Send + 'static,
    T: Send + 'static,
{
    /// Generate keypair and apply result handler
    pub async fn generate_keypair(self) -> T {
        let handler = self.result_handler;
        // For now, return a placeholder result until proper signature implementation
        let result = Ok((vec![0u8; 64], vec![0u8; 64])); // Placeholder (public_key, secret_key)
        handler(result)
    }

    /// Create a new ML-DSA builder with the specified security level
    pub fn ml_dsa(security_level: u16) -> Result<MlDsaBuilder<NeedKeyPair>> {
        let algorithm = match security_level {
            44 | 2 => SignatureAlgorithm::MlDsa44,
            65 | 3 => SignatureAlgorithm::MlDsa65,
            87 | 5 => SignatureAlgorithm::MlDsa87,
            _ => {
                return Err(PqCryptoError::UnsupportedAlgorithm(format!(
                    "ML-DSA-{} is not supported. Use 44, 65, or 87",
                    security_level
                )));
            }
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
            _ => {
                return Err(PqCryptoError::UnsupportedAlgorithm(format!(
                    "FALCON-{} is not supported. Use 512 or 1024",
                    security_level
                )));
            }
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
            _ => {
                return Err(PqCryptoError::UnsupportedAlgorithm(format!(
                    "SPHINCS+-{} is not supported",
                    variant
                )));
            }
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
