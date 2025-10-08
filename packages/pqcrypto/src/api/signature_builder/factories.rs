//! Algorithm factory methods for creating specific signature builders

use super::super::states::NeedKeyPair;
use super::core::SignatureBuilderWithHandler;
use super::{FalconBuilder, MlDsaBuilder, SphincsBuilder};
use crate::{PqCryptoError, Result, SignatureAlgorithm};
use std::marker::PhantomData;

impl<F, T> SignatureBuilderWithHandler<F, T>
where
    F: FnOnce(crate::Result<(Vec<u8>, Vec<u8>)>) -> T + Send + 'static,
    T: Send + 'static,
{
    /// Create a new ML-DSA builder with the specified security level
    pub fn ml_dsa(security_level: u16) -> Result<MlDsaBuilder<NeedKeyPair>> {
        let algorithm = match security_level {
            44 | 2 => SignatureAlgorithm::MlDsa44,
            65 | 3 => SignatureAlgorithm::MlDsa65,
            87 | 5 => SignatureAlgorithm::MlDsa87,
            _ => {
                return Err(PqCryptoError::UnsupportedAlgorithm(format!(
                    "ML-DSA-{security_level} is not supported. Use 44, 65, or 87"
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
                    "FALCON-{security_level} is not supported. Use 512 or 1024"
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
                    "SPHINCS+-{variant} is not supported"
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
