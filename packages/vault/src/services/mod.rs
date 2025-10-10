//! Core services for vault operations
//!
//! This module provides reusable, composable services that can be used throughout
//! the vault implementation. Services are abstractions over specific functionality
//! that can have multiple implementations.
//!
//! ## Available Services
//!
//! ### Key Storage
//! Abstraction over key storage backends for PQCrypto keys:
//! - `KeychainStorage` - OS keychain (macOS, Windows, Linux)
//! - Future: FileStorage, EnvStorage, CloudStorage
//!
//! ### PQCrypto Armor
//! Post-quantum cryptographic protection for vault files:
//! - `PQCryptoArmorService` - Armor/unarmor operations using ML-KEM + AES

pub mod armor;
pub mod key_storage;
pub mod encryption;

pub use armor::PQCryptoArmorService;
pub use key_storage::{KeyStorage, KeychainStorage, FileStorage, KeyStorageBackend};
pub use encryption::EncryptionService;
