//! Cryptographically secure key generation module - Decomposed modules
//!
//! This module provides the main generator traits, builder patterns, and core types
//! for secure key generation with logical separation of concerns.

// Declare submodules
pub mod derive;
pub mod entropy;
pub mod symmetric;

// Declare decomposed modules
pub mod builder_types;
pub mod core_types;
pub mod generation;
pub mod handler;

// Re-export main types and functions for convenience
pub use builder_types::{
    KeyGenerator, KeyGeneratorReady, KeyGeneratorWithSize, KeyGeneratorWithSizeAndStore,
    KeyGeneratorWithSizeStoreAndNamespace,
};
pub use core_types::StreamConfig;
pub use handler::KeyGeneratorWithHandler;
