//! ML-DSA (Module-Lattice-Based Digital Signature Algorithm) implementation

pub mod base_trait;
pub mod builder_methods;
pub mod key_management;
pub mod signing;
pub mod types;
pub mod verification;

// Re-export main types and type aliases
pub use types::{
    MlDsaBuilder, MlDsaWithKeyPair, MlDsaWithMessage, MlDsaWithPublicKey, MlDsaWithSecretKey,
    MlDsaWithSignature,
};
