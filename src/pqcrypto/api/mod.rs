//! API module for post-quantum cryptography builders

mod builder_traits;
mod kem_builder;
mod signature_builder;
mod states;

// Re-export all public types
pub use self::builder_traits::{
    KemKeyPairBuilder, SignatureKeyPairBuilder,
    EncapsulateBuilder, DecapsulateBuilder,
    SignBuilder, VerifyBuilder,
    AsyncEncapsulationResult, AsyncDecapsulationResult,
    AsyncSignatureResult, AsyncVerificationResult,
};

pub use self::kem_builder::{
    KemBuilder, MlKemBuilder,
    MlKemWithKeyPair, MlKemWithPublicKey, MlKemWithSecretKey,
    MlKemWithCiphertext,
};

pub use self::signature_builder::{
    SignatureBuilder, MlDsaBuilder, FalconBuilder, SphincsBuilder,
    MlDsaWithKeyPair, MlDsaWithSecretKey, MlDsaWithPublicKey,
    MlDsaWithMessage, MlDsaWithSignature,
    FalconWithKeyPair, FalconWithSecretKey, FalconWithPublicKey,
    FalconWithMessage, FalconWithSignature,
    SphincsWithKeyPair, SphincsWithSecretKey, SphincsWithPublicKey,
    SphincsWithMessage, SphincsWithSignature,
};

pub use self::states::{
    NeedKeyPair, HasKeyPair, HasPublicKey, HasSecretKey,
    NeedMessage, HasMessage, NeedSignature, HasSignature,
    NeedCiphertext, HasCiphertext,
};

// Re-export async traits for easier access
pub use std::future::Future;
pub use std::pin::Pin;