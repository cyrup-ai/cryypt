//! Entry point for the fluent hashing API following README.md patterns exactly

use super::blake2b_builder::Blake2bBuilder;
use super::sha3_builder::{Sha3_256Builder, Sha3_384Builder, Sha3_512Builder};
use super::sha256_builder::Sha256Builder;

/// Entry point for hash operations - README.md pattern
pub struct Hash;

impl Hash {
    /// Use SHA-256 - README.md pattern
    #[must_use]
    pub fn sha256() -> Sha256Builder {
        Sha256Builder::new()
    }

    /// Use SHA3-256 - README.md pattern  
    #[must_use]
    pub fn sha3_256() -> Sha3_256Builder {
        Sha3_256Builder::new()
    }

    /// Use SHA3-384 - README.md pattern
    #[must_use]
    pub fn sha3_384() -> Sha3_384Builder {
        Sha3_384Builder::new()
    }

    /// Use SHA3-512 - README.md pattern  
    #[must_use]
    pub fn sha3_512() -> Sha3_512Builder {
        Sha3_512Builder::new()
    }

    /// Use Blake2b - README.md pattern
    #[must_use]
    pub fn blake2b() -> Blake2bBuilder {
        Blake2bBuilder::new()
    }
}
