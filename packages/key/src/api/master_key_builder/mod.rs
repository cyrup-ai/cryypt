//! Master key builder - core types and entry point
//!
//! Contains the main entry point, builder types, and type-state markers for master key operations.

use zeroize::Zeroizing;

pub mod providers;

pub use providers::*;

/// Builder for master key
pub struct MasterKeyBuilder;

impl MasterKeyBuilder {
    /// Create master key from passphrase
    #[must_use]
    pub fn from_passphrase(passphrase: &str) -> PassphraseMasterKey {
        PassphraseMasterKey {
            passphrase: Zeroizing::new(passphrase.to_string()),
        }
    }
}
