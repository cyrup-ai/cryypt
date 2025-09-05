//! API module for post-quantum cryptography builders

mod builder_traits;
mod kem_builder;
mod signature_builder;
mod states;
mod kyber_builder;
mod dilithium_builder;
mod pqcrypto_master_builder;

// Re-export all public types
pub use self::builder_traits::{
    AsyncDecapsulationResult, AsyncEncapsulationResult, AsyncSignatureResult,
    AsyncVerificationResult, CiphertextBuilder, DecapsulateBuilder, EncapsulateBuilder,
    KemKeyPairBuilder, MessageBuilder, SignBuilder, SignatureDataBuilder, SignatureKeyPairBuilder,
    VerifyBuilder,
};

pub use self::kem_builder::{
    KemBuilder, MlKemBuilder, MlKemWithCiphertext, MlKemWithKeyPair, MlKemWithPublicKey,
    MlKemWithSecretKey,
};

pub use self::signature_builder::{
    FalconBuilder, FalconWithKeyPair, FalconWithMessage, FalconWithPublicKey, FalconWithSecretKey,
    FalconWithSignature, MlDsaBuilder, MlDsaWithKeyPair, MlDsaWithMessage, MlDsaWithPublicKey,
    MlDsaWithSecretKey, MlDsaWithSignature, SignatureBuilder, SphincsBuilder, SphincsWithKeyPair,
    SphincsWithMessage, SphincsWithPublicKey, SphincsWithSecretKey, SphincsWithSignature,
};

pub use self::states::{
    HasCiphertext, HasKeyPair, HasMessage, HasPublicKey, HasSecretKey, HasSignature,
    NeedCiphertext, NeedKeyPair, NeedMessage, NeedSignature,
};

pub use self::kyber_builder::{KyberBuilder, KyberBuilderWithHandler, KyberBuilderWithChunk, SecurityLevel as KyberSecurityLevel, HasSecurityLevel as KyberHasSecurityLevel, NoSecurityLevel as KyberNoSecurityLevel};
pub use self::dilithium_builder::{DilithiumBuilder, DilithiumBuilderWithHandler, DilithiumBuilderWithChunk, SecurityLevel as DilithiumSecurityLevel};
pub use self::pqcrypto_master_builder::PqCryptoMasterBuilder;

// Re-export async traits for easier access
pub use std::future::Future;
pub use std::pin::Pin;
