//! Core Master Builder
//!
//! Main entry point for all cryypt operations following README.md patterns

#[cfg(feature = "jwt")]
use cryypt_jwt::Cryypt as JwtCryypt;

#[cfg(any(feature = "aes", feature = "chacha20"))]
use super::CipherMasterBuilder;

#[cfg(any(feature = "zstd", feature = "gzip", feature = "bzip2", feature = "zip"))]
use super::CompressMasterBuilder;

#[cfg(any(feature = "sha256", feature = "sha3", feature = "blake2b"))]
use super::HashMasterBuilder;

#[cfg(feature = "key")]
use super::KeyMasterBuilder;

#[cfg(feature = "pqcrypto")]
use super::PqcryptoMasterBuilder;

#[cfg(feature = "quic")]
use super::QuicMasterBuilder;

#[cfg(feature = "vault")]
use super::VaultMasterBuilder;

/// Master builder providing unified entry point for all cryypt operations
/// README.md pattern: "Cryypt offers two equivalent APIs"
pub struct Cryypt;

impl Cryypt {
    /// Entry point for cipher operations - README.md pattern
    /// Example: `Cryypt::cipher().aes().with_key(key).encrypt(data).await`
    #[cfg(any(feature = "aes", feature = "chacha20"))]
    #[must_use]
    pub fn cipher() -> CipherMasterBuilder {
        CipherMasterBuilder
    }

    /// Entry point for hashing operations - README.md pattern
    /// Example: `Cryypt::hash().sha256().compute(data).await`
    #[cfg(any(feature = "sha256", feature = "sha3", feature = "blake2b"))]
    #[must_use]
    pub fn hash() -> HashMasterBuilder {
        HashMasterBuilder
    }

    /// Entry point for compression operations - README.md pattern
    /// Example: `Cryypt::compress().zstd().compress(data).await`
    #[cfg(any(feature = "zstd", feature = "gzip", feature = "bzip2", feature = "zip"))]
    #[must_use]
    pub fn compress() -> CompressMasterBuilder {
        CompressMasterBuilder
    }

    /// Entry point for JWT operations - README.md pattern
    /// Example: `Cryypt::jwt().hs256().with_secret(secret).sign().await`
    #[cfg(feature = "jwt")]
    #[must_use]
    pub fn jwt() -> cryypt_jwt::JwtMasterBuilder {
        JwtCryypt::jwt()
    }

    /// Entry point for key operations - README.md pattern
    /// Example: `Cryypt::key().size(256.bits()).with_store(store).generate().await`
    #[cfg(feature = "key")]
    #[must_use]
    pub fn key() -> KeyMasterBuilder {
        KeyMasterBuilder
    }

    /// Entry point for vault operations - README.md pattern
    /// Example: `Cryypt::vault().with_config(config).create().await`
    #[cfg(feature = "vault")]
    #[must_use]
    pub fn vault() -> VaultMasterBuilder {
        VaultMasterBuilder
    }

    /// Entry point for post-quantum cryptography operations - README.md pattern
    /// Example: `Cryypt::pqcrypto().kyber().generate_keypair().await`
    #[cfg(feature = "pqcrypto")]
    #[must_use]
    pub fn pqcrypto() -> PqcryptoMasterBuilder {
        PqcryptoMasterBuilder
    }

    /// Entry point for QUIC operations - README.md pattern
    /// Example: `Cryypt::quic().server().with_cert(cert).bind(addr).await`
    #[cfg(feature = "quic")]
    #[must_use]
    pub fn quic() -> QuicMasterBuilder {
        QuicMasterBuilder
    }
}
