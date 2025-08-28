//! Production-ready KEM (Key Encapsulation Mechanism) builder module
//!
//! Implements ML-KEM (FIPS 203) with zero allocation and blazing-fast performance.

// Declare submodules
pub mod decapsulation;
pub mod encapsulation;
pub mod keypair;

// Declare new decomposed modules
pub mod builder;
pub mod core;
pub mod handlers;
pub mod operations;

// Re-export everything from core module
pub use core::*;

// Re-export key types from submodules for external use
pub use decapsulation::*;
pub use keypair::*;
