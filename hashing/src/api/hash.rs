//! Entry point for the fluent hashing API

use super::{HashBuilder, NoData, NoPasses, NoSalt};

/// Entry point for hash operations
pub struct Hash;

impl Hash {
    /// Use SHA-256
    pub fn sha256() -> HashBuilder<Sha256Hash, NoData, NoSalt, NoPasses> {
        HashBuilder {
            hasher: Sha256Hash,
            data: NoData,
            salt: NoSalt,
            passes: NoPasses,
        }
    }

    /// Use SHA3-256
    pub fn sha3() -> HashBuilder<Sha3_256Hash, NoData, NoSalt, NoPasses> {
        HashBuilder {
            hasher: Sha3_256Hash,
            data: NoData,
            salt: NoSalt,
            passes: NoPasses,
        }
    }

    /// Use SHA3-384
    pub fn sha3_384() -> HashBuilder<Sha3_384Hash, NoData, NoSalt, NoPasses> {
        HashBuilder {
            hasher: Sha3_384Hash,
            data: NoData,
            salt: NoSalt,
            passes: NoPasses,
        }
    }

    /// Use SHA3-512
    pub fn sha3_512() -> HashBuilder<Sha3_512Hash, NoData, NoSalt, NoPasses> {
        HashBuilder {
            hasher: Sha3_512Hash,
            data: NoData,
            salt: NoSalt,
            passes: NoPasses,
        }
    }

    /// Use Blake2b
    pub fn blake2b() -> HashBuilder<Blake2bHash, NoData, NoSalt, NoPasses> {
        HashBuilder {
            hasher: Blake2bHash { output_size: 64 },
            data: NoData,
            salt: NoSalt,
            passes: NoPasses,
        }
    }
}

// Marker types for different hash algorithms
/// SHA-256 hash algorithm implementation
pub struct Sha256Hash;
/// SHA3-256 hash algorithm implementation
pub struct Sha3_256Hash;
/// SHA3-384 hash algorithm implementation
pub struct Sha3_384Hash;
/// SHA3-512 hash algorithm implementation
pub struct Sha3_512Hash;
/// BLAKE2b hash algorithm implementation with configurable output size
pub struct Blake2bHash {
    /// Output size in bytes (1-64)
    pub output_size: u8,
}
