//! File-based Key Storage Implementation
//!
//! This module provides a complete file-based key storage solution with AES-GCM encryption,
//! async operations, and comprehensive trait implementations for key management.

mod core;
mod encryption;
mod legacy_api;
mod storage_traits;

// Re-export public types
pub use core::{FileKeyStore, FileKeyStoreBuilder};

// Internal modules are not re-exported as they contain implementation details
