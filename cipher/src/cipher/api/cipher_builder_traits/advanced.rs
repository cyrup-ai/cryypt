//! Advanced cipher operations
//!
//! Contains traits for two-pass encryption/decryption and compression integration.

use super::base::{DecryptBuilder, EncryptBuilder};
use super::data::{CiphertextBuilder, DataBuilder};
use super::super::{AsyncDecryptionResult, AsyncEncryptionResult};
use crate::CryptError;

/// Extension trait for decryption second pass
pub trait DecryptSecondPass: DecryptBuilder + Sized {
    /// Add a second decryption pass for two-pass ciphers
    fn second_pass<C>(self, second_cipher: C) -> TwoPassDecryptWrapper<Self, C> {
        TwoPassDecryptWrapper {
            first: self,
            second: second_cipher,
        }
    }
}

/// Extension trait for encryption second pass
pub trait EncryptSecondPass: EncryptBuilder + Sized {
    /// Add a second encryption pass for two-pass ciphers
    fn second_pass<C>(self, second_cipher: C) -> TwoPassEncryptWrapper<Self, C> {
        TwoPassEncryptWrapper {
            first: self,
            second: second_cipher,
        }
    }
}

// Blanket implementations
impl<T: EncryptBuilder + Sized> EncryptSecondPass for T {}
impl<T: DecryptBuilder + Sized> DecryptSecondPass for T {}

/// Wrapper for two-pass encryption operations
pub struct TwoPassEncryptWrapper<First, Second> {
    first: First,
    second: Second,
}

impl<First, Second> EncryptBuilder for TwoPassEncryptWrapper<First, Second>
where
    First: EncryptBuilder + Send + 'static,
    Second: DataBuilder + Send + 'static,
    <Second as DataBuilder>::Output: EncryptBuilder + Send + 'static,
{
    fn encrypt(self) -> impl AsyncEncryptionResult {
        async move {
            // First pass encryption
            let first_result = self.first.encrypt().await?;

            // Second pass: use first result as data for second cipher
            self.second.with_data(first_result).encrypt().await
        }
    }
}

/// Wrapper for two-pass decryption operations
pub struct TwoPassDecryptWrapper<First, Second> {
    first: First,
    second: Second,
}

impl<First, Second> DecryptBuilder for TwoPassDecryptWrapper<First, Second>
where
    First: DecryptBuilder + Send + 'static,
    Second: CiphertextBuilder + Send + 'static,
    <Second as CiphertextBuilder>::Output: DecryptBuilder + Send + 'static,
{
    fn decrypt(self) -> impl AsyncDecryptionResult {
        async move {
            // First pass decryption
            let first_result = self.first.decrypt().await?;

            // Second pass: use first result as ciphertext for second cipher
            self.second.with_ciphertext(first_result).decrypt().await
        }
    }
}

/// Extension trait to add compression to any cipher with key
/// Support for compression
pub trait WithCompression: Sized {
    /// Add compression to this cipher operation
    fn with_compression<C>(self, compression: C) -> CompressionWrapper<Self, C> {
        CompressionWrapper {
            cipher: self,
            compression,
        }
    }
}

// Blanket implementation for any type that has a key configured
impl<T: Sized> WithCompression for T {}

/// Wrapper that adds compression to cipher operations
pub struct CompressionWrapper<Cipher, Compression> {
    cipher: Cipher,
    compression: Compression,
}

// CompressionWrapper can accept data and encrypt with compression
impl<Cipher, Compression> DataBuilder for CompressionWrapper<Cipher, Compression>
where
    Cipher: DataBuilder,
{
    type Output = CompressionDataWrapper<Cipher::Output, Compression>;

    fn with_data<T: Into<Vec<u8>>>(self, data: T) -> Self::Output {
        CompressionDataWrapper {
            cipher_with_data: self.cipher.with_data(data),
            compression: self.compression,
        }
    }
}

// CompressionWrapper can accept ciphertext and decrypt with decompression
impl<Cipher, Compression> CiphertextBuilder for CompressionWrapper<Cipher, Compression>
where
    Cipher: CiphertextBuilder,
{
    type Output = CompressionCiphertextWrapper<Cipher::Output, Compression>;

    fn with_ciphertext<T: Into<Vec<u8>>>(self, ciphertext: T) -> Self::Output {
        CompressionCiphertextWrapper {
            cipher_with_ciphertext: self.cipher.with_ciphertext(ciphertext),
            compression: self.compression,
        }
    }
}

/// Wrapper for compression with data already provided to cipher
pub struct CompressionDataWrapper<CipherWithData, Compression> {
    cipher_with_data: CipherWithData,
    compression: Compression,
}

// Specific implementation for AES with compression
impl<Compression> EncryptBuilder
    for CompressionDataWrapper<super::super::aes_builder::AesWithKeyAndData, Compression>
where
    Compression: cryypt_compression::api::DataBuilder + Send + 'static,
    <Compression as cryypt_compression::api::DataBuilder>::Output:
        cryypt_compression::api::CompressExecutor + Send + 'static,
{
    fn encrypt(self) -> impl AsyncEncryptionResult {
        async move {
            // Compress the data first
            use cryypt_compression::api::CompressExecutor;
            let compressed_data = self
                .compression
                .with_data(self.cipher_with_data.data.clone())
                .compress()
                .await
                .map_err(|e| CryptError::from(e))?;

            // Create new AES builder with compressed data and encrypt
            super::super::aes_builder::AesWithKeyAndData {
                key_builder: self.cipher_with_data.key_builder,
                data: compressed_data,
                aad: std::collections::HashMap::new(),
            }
            .encrypt()
            .await
        }
    }
}

// Specific implementation for ChaCha with compression
impl<Compression> EncryptBuilder
    for CompressionDataWrapper<super::super::chacha_builder::ChaChaWithKeyAndData, Compression>
where
    Compression: cryypt_compression::api::DataBuilder + Send + 'static,
    <Compression as cryypt_compression::api::DataBuilder>::Output:
        cryypt_compression::api::CompressExecutor + Send + 'static,
{
    fn encrypt(self) -> impl AsyncEncryptionResult {
        async move {
            // Compress the data first
            use cryypt_compression::api::CompressExecutor;
            let compressed_data = self
                .compression
                .with_data(self.cipher_with_data.data.clone())
                .compress()
                .await
                .map_err(|e| CryptError::from(e))?;

            // Create new ChaCha builder with compressed data and encrypt
            super::super::chacha_builder::ChaChaWithKeyAndData {
                key_builder: self.cipher_with_data.key_builder,
                data: compressed_data,
            }
            .encrypt()
            .await
        }
    }
}

/// Wrapper for compression with ciphertext already provided to cipher
pub struct CompressionCiphertextWrapper<CipherWithCiphertext, Compression> {
    cipher_with_ciphertext: CipherWithCiphertext,
    compression: Compression,
}

// Specific implementation for AES with decompression
impl<Compression> DecryptBuilder
    for CompressionCiphertextWrapper<super::super::aes_builder::AesWithKeyAndCiphertext, Compression>
where
    Compression: cryypt_compression::api::DataBuilder + Send + 'static,
    <Compression as cryypt_compression::api::DataBuilder>::Output:
        cryypt_compression::api::DecompressExecutor + Send + 'static,
{
    fn decrypt(self) -> impl AsyncDecryptionResult {
        async move {
            // Decrypt first
            let decrypted_data = self.cipher_with_ciphertext.decrypt().await?;

            // Then decompress
            use cryypt_compression::api::DecompressExecutor;
            self.compression
                .with_data(decrypted_data)
                .decompress()
                .await
                .map_err(|e| CryptError::from(e))
        }
    }
}

// Specific implementation for ChaCha with decompression
impl<Compression> DecryptBuilder
    for CompressionCiphertextWrapper<super::super::chacha_builder::ChaChaWithKeyAndCiphertext, Compression>
where
    Compression: cryypt_compression::api::DataBuilder + Send + 'static,
    <Compression as cryypt_compression::api::DataBuilder>::Output:
        cryypt_compression::api::DecompressExecutor + Send + 'static,
{
    fn decrypt(self) -> impl AsyncDecryptionResult {
        async move {
            // Decrypt first
            let decrypted_data = self.cipher_with_ciphertext.decrypt().await?;

            // Then decompress
            use cryypt_compression::api::DecompressExecutor;
            self.compression
                .with_data(decrypted_data)
                .decompress()
                .await
                .map_err(|e| CryptError::from(e))
        }
    }
}