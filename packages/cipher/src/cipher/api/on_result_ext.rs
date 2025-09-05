//! Extension trait for on_result! macro support in cipher operations

use crate::Result;
use std::future::Future;

/// Extension trait that adds on_result! method to cipher builders
pub trait CipherOnResultExt: Sized {
    /// The output type for encryption operations
    type EncryptOutput;
    /// The output type for decryption operations  
    type DecryptOutput;
    
    /// The future type returned by encrypt
    type EncryptFuture: Future<Output = Self::EncryptOutput>;
    /// The future type returned by decrypt
    type DecryptFuture: Future<Output = Self::DecryptOutput>;
    
    /// Encrypt data - implemented by each cipher
    fn encrypt<T: Into<Vec<u8>> + Send + 'static>(self, data: T) -> Self::EncryptFuture;
    
    /// Decrypt data - implemented by each cipher
    fn decrypt(self, ciphertext: &[u8]) -> Self::DecryptFuture;
    
    /// Method that the on_result! macro expands to for encryption
    #[inline]
    fn on_result_encrypt<F>(self, _handler: F, data: Vec<u8>) -> Self::EncryptFuture 
    where
        F: FnOnce(&mut dyn FnMut(Self::EncryptOutput) -> Self::EncryptOutput),
    {
        // The handler is ignored - it's just for syntax compatibility
        // The macro will replace this entire call with encrypt()
        self.encrypt(data)
    }
    
    /// Method that the on_result! macro expands to for decryption
    #[inline]
    fn on_result_decrypt<F>(self, _handler: F, ciphertext: &[u8]) -> Self::DecryptFuture 
    where
        F: FnOnce(&mut dyn FnMut(Self::DecryptOutput) -> Self::DecryptOutput),
    {
        // The handler is ignored - it's just for syntax compatibility
        // The macro will replace this entire call with decrypt()
        self.decrypt(ciphertext)
    }
}

/// Producer trait for cipher operations that work with on_result!
pub trait CipherProducer: Sized {
    /// Produce encryption result
    async fn produce_encrypt(self, data: Vec<u8>) -> Result<Vec<u8>>;
    
    /// Produce decryption result
    async fn produce_decrypt(self, ciphertext: &[u8]) -> Result<Vec<u8>>;
}