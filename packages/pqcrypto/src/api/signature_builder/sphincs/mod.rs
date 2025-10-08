//! SPHINCS+ (Stateless Hash-based Digital Signature Scheme) implementation
//!
//! This module provides decomposed SPHINCS+ signature operations organized by functional responsibility.

pub mod builders;
pub mod core;
pub mod keypair;
pub mod signing;
pub mod types;
pub mod verification;

// Re-export main types for easy access
pub use core::SphincsBuilder;
pub use types::{
    SphincsWithKeyPair, SphincsWithMessage, SphincsWithPublicKey, SphincsWithSecretKey,
    SphincsWithSignature,
};
