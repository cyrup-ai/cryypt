//! Entry point for key operations

use super::{Key256Builder, RawKeyBuilder};
use crate::bits_macro::BitSize;
use crate::{KeyError, Result};

/// Entry point for key operations
pub struct Key;

impl Key {
    /// Create a key with specified bit size
    pub fn size(size: BitSize) -> Result<Key256Builder> {
        match size.bits {
            256 => Ok(Key256Builder),
            _ => Err(KeyError::InvalidKey(format!(
                "Unsupported key size: {} bits. Only 256-bit keys are currently supported.",
                size.bits
            ))),
        }
    }

    /// Create a 256-bit (32-byte) key suitable for AES-256-GCM, ChaCha20-Poly1305, etc.
    pub fn bits_256() -> Key256Builder {
        Key256Builder
    }

    /// Use an existing key from raw bytes
    pub fn from_bytes(key: Vec<u8>) -> RawKeyBuilder {
        RawKeyBuilder::from_bytes(key)
    }
}
