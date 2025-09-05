//! Core SHA3 Hasher Types and Utilities
//!
//! This module provides the core hasher types and trait implementations
//! for SHA3 variants, including the DynHasher trait for dynamic dispatch.

use super::super::stream::DynHasher;

/// SHA3-256 hasher wrapper
pub struct Sha3_256Hasher(pub(crate) sha3::Sha3_256);

/// SHA3-384 hasher wrapper  
pub struct Sha3_384Hasher(pub(crate) sha3::Sha3_384);

/// SHA3-512 hasher wrapper
pub struct Sha3_512Hasher(pub(crate) sha3::Sha3_512);

// Re-export the DynHasher trait for use in other modules
pub use super::super::stream::DynHasher;