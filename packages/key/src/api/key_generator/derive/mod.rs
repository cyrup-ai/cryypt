//! Key Derivation - Decomposed modules for secure key derivation operations
//!
//! This module provides production-ready key derivation functionality with PBKDF2,
//! Argon2, and HKDF implementations featuring zero allocation and blazing-fast performance.

pub mod config;
pub mod core;
pub mod specialized;
pub mod utils;

// Re-export main types and functions for convenience
pub use config::{KdfAlgorithm, KdfConfig};
pub use core::KeyDerivation;
pub use specialized::{FastKeyDerivation, KeyStretcher};
pub use utils::{constant_time_compare, derive_key_auto};
