//! Entry point for the fluent cipher API

use super::{
    aes_builder::AesBuilder,
    chacha_builder::ChaChaBuilder,
    decryption_builder::DecryptionBuilder,
    HasData,
};

/// Entry point for cipher operations
pub struct Cipher;

impl Cipher {
    /// Use AES-256-GCM
    pub fn aes() -> AesBuilder {
        AesBuilder::new()
    }
    
    /// Use ChaCha20-Poly1305
    pub fn chachapoly() -> ChaChaBuilder {
        ChaChaBuilder::new()
    }
    
    /// Decrypt data
    pub fn decrypt(encrypted: Vec<u8>) -> DecryptionBuilder<(), HasData<Vec<u8>>> {
        DecryptionBuilder {
            _cipher: (),
            data: HasData(encrypted),
        }
    }
}