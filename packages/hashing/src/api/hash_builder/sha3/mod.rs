//! SHA3 Hash Implementation Module
//!
//! This module provides complete SHA3 hash implementations for all variants
//! (256, 384, 512) with both regular hashing and HMAC support.

pub mod core;
pub mod sha3_256;
pub mod sha3_384;
pub mod sha3_512;

// Re-export core types
pub use core::{Sha3_256Hasher, Sha3_384Hasher, Sha3_512Hasher, DynHasher};

// Re-export hash functions for internal use
pub use sha3_256::{sha3_256_hash, sha3_256_hmac};
pub use sha3_384::{sha3_384_hash, sha3_384_hmac};
pub use sha3_512::{sha3_512_hash, sha3_512_hmac};