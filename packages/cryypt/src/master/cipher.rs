//! Cipher Master Builder
//!
//! Master builder for cipher operations (AES, `ChaCha20`)

/// Master builder for cipher operations
#[cfg(any(feature = "aes", feature = "chacha20"))]
pub struct CipherMasterBuilder;

#[cfg(any(feature = "aes", feature = "chacha20"))]
impl CipherMasterBuilder {
    /// Use AES-256-GCM encryption - README.md pattern
    #[cfg(feature = "aes")]
    #[must_use]
    pub fn aes(self) -> cryypt_cipher::AesBuilder {
        cryypt_cipher::Cipher::aes()
    }

    /// Use ChaCha20-Poly1305 encryption - README.md pattern
    #[cfg(feature = "chacha20")]
    #[must_use]
    pub fn chacha20(self) -> cryypt_cipher::ChaChaBuilder {
        cryypt_cipher::Cipher::chacha20()
    }

    /// Use ChaCha20-Poly1305 encryption (alias) - README.md pattern
    #[cfg(feature = "chacha20")]
    #[must_use]
    pub fn chachapoly(self) -> cryypt_cipher::ChaChaBuilder {
        cryypt_cipher::Cipher::chacha20()
    }
}
