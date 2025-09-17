//! Master key builder - core types and entry point
//!
//! Contains the main entry point, builder types, and type-state markers for master key operations.

use crate::bits_macro::BitSize;
use crate::{KeyStorage, KeyError, Result};

pub mod builders;
pub mod providers;
pub mod stored;

pub use builders::*;
pub use providers::*;
pub use stored::*;

/// Master key entry point
pub struct MasterKey;

impl MasterKey {
    /// Create a master key of specified size
    pub fn size(size: BitSize) -> Result<MasterKeyBuilder> {
        match size.bits {
            256 => Ok(MasterKeyBuilder),
            _ => Err(KeyError::InvalidKey(format!(
                "Master keys must be 256 bits, got {} bits",
                size.bits
            ))),
        }
    }

    /// Create master key from hex string
    pub fn from_hex(hex_str: &str) -> crate::Result<RawMasterKey> {
        MasterKeyBuilder::from_hex(hex_str)
    }

    /// Create master key from base64 string
    pub fn from_base64(base64_str: &str) -> crate::Result<RawMasterKey> {
        MasterKeyBuilder::from_base64(base64_str)
    }

    /// Create master key from passphrase
    pub fn from_passphrase(passphrase: &str) -> PassphraseMasterKey {
        MasterKeyBuilder::from_passphrase(passphrase)
    }

    /// Create master key from environment variable
    pub fn from_env(var_name: &str) -> EnvMasterKey {
        MasterKeyBuilder::from_env(var_name)
    }
}

/// Builder for master key
pub struct MasterKeyBuilder;

/// Master key builder with store configured
pub struct MasterKeyBuilderWithStore<S: KeyStorage> {
    pub(crate) store: S,
}

/// Master key builder with store and namespace configured  
pub struct MasterKeyBuilderWithStoreAndNamespace<S: KeyStorage> {
    pub(crate) store: S,
    pub(crate) namespace: String,
}

/// Master key builder with store, namespace, and version configured
pub struct MasterKeyBuilderWithStoreNamespaceAndVersion<S: KeyStorage> {
    pub(crate) store: S,
    pub(crate) namespace: String,
    pub(crate) version: u32,
}