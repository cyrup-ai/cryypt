//! API module for post-quantum cryptography builders

mod builder_traits;
mod dilithium_builder;
mod kem_builder;
mod kyber_builder;
mod pqcrypto_master_builder;
mod signature_builder;
mod states;

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

pub use self::dilithium_builder::{
    DilithiumBuilder, DilithiumBuilderWithChunk, DilithiumBuilderWithHandler,
    SecurityLevel as DilithiumSecurityLevel,
};
pub use self::kyber_builder::{
    HasSecurityLevel as KyberHasSecurityLevel, KyberBuilder, KyberBuilderWithChunk,
    KyberBuilderWithHandler, NoSecurityLevel as KyberNoSecurityLevel,
    SecurityLevel as KyberSecurityLevel,
};
pub use self::pqcrypto_master_builder::PqCryptoMasterBuilder;

// Re-export async traits for easier access
pub use std::future::Future;
pub use std::pin::Pin;
