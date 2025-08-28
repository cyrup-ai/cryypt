//! Master builder for all cryypt operations following README.md patterns
//!
//! This module provides the unified entry point for all cryypt operations,
//! decomposed into logical components by operation type.

pub mod cipher;
pub mod compression;
pub mod core;
pub mod hash;
pub mod key;
pub mod pqcrypto;
pub mod quic;
pub mod vault;
pub mod vault_impl;

// Re-export main types
pub use core::Cryypt;

#[cfg(any(feature = "aes", feature = "chacha20"))]
pub use cipher::CipherMasterBuilder;

#[cfg(any(feature = "sha256", feature = "sha3", feature = "blake2b"))]
pub use hash::HashMasterBuilder;

#[cfg(any(feature = "zstd", feature = "gzip", feature = "bzip2", feature = "zip"))]
pub use compression::CompressMasterBuilder;

#[cfg(feature = "key")]
pub use key::KeyMasterBuilder;

#[cfg(feature = "vault")]
pub use vault::VaultMasterBuilder;

#[cfg(feature = "pqcrypto")]
pub use pqcrypto::PqcryptoMasterBuilder;

#[cfg(feature = "quic")]
pub use quic::QuicMasterBuilder;
