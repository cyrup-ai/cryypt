//! Entry point for the fluent cipher API following README.md patterns exactly

use super::{aes_builder::AesBuilder, chacha_builder::ChaChaBuilder};

/// Entry point for cipher operations - README.md pattern
pub struct Cipher;

impl Cipher {
    /// Use AES-256-GCM (recommended for most use cases) - README.md pattern
    pub fn aes() -> AesBuilder {
        AesBuilder::new()
    }

    /// Use ChaCha20-Poly1305 (recommended for mobile/low-power devices) - README.md pattern
    pub fn chachapoly() -> ChaChaBuilder {
        ChaChaBuilder::new()
    }
}