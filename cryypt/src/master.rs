//! Master builder for all cryypt operations following README.md patterns

#[cfg(any(feature = "aes", feature = "chacha20"))]
use cryypt_cipher::Cipher;

#[cfg(any(feature = "sha256", feature = "sha3", feature = "blake2b"))]
use cryypt_hashing::Hash;

#[cfg(any(feature = "zstd", feature = "gzip", feature = "bzip2", feature = "zip"))]
use cryypt_compression::Compress;

#[cfg(feature = "jwt")]
use cryypt_jwt::{Cryypt as JwtCryypt};

/// Master builder providing unified entry point for all cryypt operations
/// README.md pattern: "Cryypt offers two equivalent APIs"
pub struct Cryypt;

impl Cryypt {
    /// Entry point for cipher operations - README.md pattern
    /// Example: `Cryypt::cipher().aes().with_key(key).encrypt(data).await`
    #[cfg(any(feature = "aes", feature = "chacha20"))]
    pub fn cipher() -> CipherMasterBuilder {
        CipherMasterBuilder
    }
    
    /// Entry point for hashing operations - README.md pattern
    /// Example: `Cryypt::hash().sha256().compute(data).await`
    #[cfg(any(feature = "sha256", feature = "sha3", feature = "blake2b"))]
    pub fn hash() -> HashMasterBuilder {
        HashMasterBuilder
    }
    
    /// Entry point for compression operations - README.md pattern
    /// Example: `Cryypt::compress().zstd().compress(data).await`
    #[cfg(any(feature = "zstd", feature = "gzip", feature = "bzip2", feature = "zip"))]
    pub fn compress() -> CompressMasterBuilder {
        CompressMasterBuilder
    }
    
    /// Entry point for JWT operations - README.md pattern
    /// Example: `Cryypt::jwt().hs256().with_secret(secret).sign().await`
    #[cfg(feature = "jwt")]
    pub fn jwt() -> cryypt_jwt::api::JwtMasterBuilder {
        JwtCryypt::jwt()
    }
}

/// Master builder for cipher operations
#[cfg(any(feature = "aes", feature = "chacha20"))]
pub struct CipherMasterBuilder;

#[cfg(any(feature = "aes", feature = "chacha20"))]
impl CipherMasterBuilder {
    /// Use AES-256-GCM encryption - README.md pattern
    #[cfg(feature = "aes")]
    pub fn aes(self) -> cryypt_cipher::cipher::api::aes_builder::AesBuilder {
        Cipher::aes()
    }
    
    /// Use ChaCha20-Poly1305 encryption - README.md pattern
    #[cfg(feature = "chacha20")]
    pub fn chachapoly(self) -> cryypt_cipher::cipher::api::chacha_builder::ChaChaBuilder {
        Cipher::chachapoly()
    }
}

/// Master builder for hashing operations
#[cfg(any(feature = "sha256", feature = "sha3", feature = "blake2b"))]
pub struct HashMasterBuilder;

#[cfg(any(feature = "sha256", feature = "sha3", feature = "blake2b"))]
impl HashMasterBuilder {
    /// Use SHA-256 hashing - README.md pattern
    #[cfg(feature = "sha256")]
    pub fn sha256(self) -> cryypt_hashing::api::hash_builder::Sha256Builder {
        Hash::sha256()
    }
    
    /// Use SHA3-256 hashing - README.md pattern
    #[cfg(feature = "sha3")]
    pub fn sha3(self) -> cryypt_hashing::api::hash_builder::Sha3Builder {
        Hash::sha3()
    }
    
    /// Use BLAKE2b hashing - README.md pattern
    #[cfg(feature = "blake2b")]
    pub fn blake2b(self) -> cryypt_hashing::api::hash_builder::Blake2bBuilder {
        Hash::blake2b()
    }
}

/// Master builder for compression operations
#[cfg(any(feature = "zstd", feature = "gzip", feature = "bzip2", feature = "zip"))]
pub struct CompressMasterBuilder;

#[cfg(any(feature = "zstd", feature = "gzip", feature = "bzip2", feature = "zip"))]
impl CompressMasterBuilder {
    /// Use Zstandard compression - README.md pattern
    #[cfg(feature = "zstd")]
    pub fn zstd(self) -> cryypt_compression::api::zstd_builder::ZstdBuilder {
        Compress::zstd()
    }
    
    /// Use Gzip compression - README.md pattern
    #[cfg(feature = "gzip")]
    pub fn gzip(self) -> cryypt_compression::api::gzip_builder::GzipBuilder {
        Compress::gzip()
    }
    
    /// Use Bzip2 compression - README.md pattern
    #[cfg(feature = "bzip2")]
    pub fn bzip2(self) -> cryypt_compression::api::bzip2_builder::Bzip2Builder {
        Compress::bzip2()
    }
}