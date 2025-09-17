//! Post-quantum cryptography module
//!
//! This module provides builders and APIs for post-quantum key encapsulation mechanisms (KEMs)
//! and digital signature algorithms that are resistant to attacks by quantum computers.
//!
//! # Supported Algorithms
//!
//! ## Key Encapsulation Mechanisms (KEMs)
//! - ML-KEM (Module-Lattice-based KEM, formerly CRYSTALS-Kyber)
//!   - ML-KEM-512 (NIST security level 1)
//!   - ML-KEM-768 (NIST security level 3)
//!   - ML-KEM-1024 (NIST security level 5)
//!
//! ## Digital Signature Algorithms
//! - ML-DSA (Module-Lattice-based Digital Signature Algorithm, formerly CRYSTALS-Dilithium)
//!   - ML-DSA-44 (NIST security level 2)
//!   - ML-DSA-65 (NIST security level 3)
//!   - ML-DSA-87 (NIST security level 5)
//! - FALCON (Fast Fourier Lattice-based Compact Signatures over NTRU)
//!   - FALCON-512 (NIST security level 1)
//!   - FALCON-1024 (NIST security level 5)
//! - SPHINCS+ (Stateless Hash-based Signatures)
//!   - Multiple parameter sets for different speed/size trade-offs

mod algorithm;
pub mod api;
mod error;
mod result;
mod shared_secret;

// Re-export error types
pub use self::error::{PqCryptoError, Result};

// Re-export main types
pub use self::algorithm::{KemAlgorithm, SignatureAlgorithm};
pub use self::result::{
    DecapsulationResult, EncapsulationResult, SignatureResult, VerificationResult,
};
pub use self::shared_secret::SharedSecret;

// Re-export builder traits
pub use self::api::{
    CiphertextBuilder, DecapsulateBuilder, EncapsulateBuilder, KemBuilder, KemKeyPairBuilder,
    MessageBuilder, PqCryptoMasterBuilder, SignBuilder, SignatureBuilder, SignatureDataBuilder,
    SignatureKeyPairBuilder, VerifyBuilder,
};

/// Prelude for post-quantum cryptography
pub mod prelude {
    pub use super::{KemAlgorithm, KemBuilder, SharedSecret, SignatureAlgorithm, SignatureBuilder};
}
