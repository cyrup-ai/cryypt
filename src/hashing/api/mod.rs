//! Fluent hashing API with zero boxing
//!
//! Usage: `let result = Hash::sha256().with_data(b"...").with_salt(b"...").with_passes(16).hash().await`

mod blake2b_builder;
mod builder_traits;
mod sha256_builder;
mod sha3_builder;

pub use blake2b_builder::Blake2bBuilder;
pub use builder_traits::*;
pub use sha256_builder::Sha256Builder;
pub use sha3_builder::Sha3Builder;

/// Entry point for hashing operations
pub struct Hash;

impl Hash {
    /// Create a SHA-256 hasher
    pub fn sha256() -> Sha256Builder {
        Sha256Builder
    }

    /// Create a SHA3-256 hasher
    pub fn sha3() -> Sha3Builder {
        Sha3Builder
    }

    /// Create a Blake2b hasher
    pub fn blake2b() -> Blake2bBuilder {
        Blake2bBuilder
    }
}
