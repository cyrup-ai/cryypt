//! Master builder for all cryypt operations

#[cfg(feature = "key")]
use cryypt_key::api::KeyBuilder;

#[cfg(any(feature = "aes", feature = "chacha20"))]
use cryypt_cipher::Cipher;

#[cfg(any(feature = "sha256", feature = "sha3", feature = "blake2b"))]
use cryypt_hashing::Hash;

#[cfg(any(feature = "zstd", feature = "gzip", feature = "bzip2", feature = "zip"))]
use cryypt_compression::Compress;

/// Master builder providing unified entry point for all cryypt operations
pub struct Cryypt;

impl Cryypt {
    /// Entry point for key operations
    #[cfg(feature = "key")]
    pub fn key() -> KeyBuilder {
        KeyBuilder::new()
    }
    
    /// Entry point for cipher operations
    #[cfg(any(feature = "aes", feature = "chacha20"))]
    pub fn cipher() -> Cipher {
        Cipher
    }
    
    /// Entry point for hashing operations
    #[cfg(any(feature = "sha256", feature = "sha3", feature = "blake2b"))]
    pub fn hash() -> Hash {
        Hash
    }
    
    /// Entry point for compression operations
    #[cfg(any(feature = "zstd", feature = "gzip", feature = "bzip2", feature = "zip"))]
    pub fn compress() -> Compress {
        Compress
    }
}