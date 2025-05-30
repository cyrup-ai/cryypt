//! Builder traits for cipher operations

use super::{AsyncDecryptionResult, AsyncEncryptionResult};

/// Builder that can accept a key
pub trait KeyBuilder {
    type Output;
    fn with_key<K>(self, key_builder: K) -> Self::Output
    where
        K: KeyProviderBuilder + 'static;
}

/// Trait for key builders that can provide keys
pub trait KeyProviderBuilder: Send + Sync {
    /// Resolve this builder to get the key material
    fn resolve(&self) -> crate::key::KeyResult;
}

/// Builder that can accept AAD (Additional Authenticated Data) for AEAD ciphers
pub trait AadBuilder {
    type Output;
    
    /// Add multiple AAD key-value pairs from a map
    fn with_aad(self, aad_map: std::collections::HashMap<String, String>) -> Self::Output;
}

/// Builder that can accept data
pub trait DataBuilder {
    type Output;
    fn with_data<T: Into<Vec<u8>>>(self, data: T) -> Self::Output;
    
    /// Accept data from a file
    fn with_file<P: AsRef<std::path::Path> + Send>(self, path: P) -> impl std::future::Future<Output = crate::Result<Self::Output>> + Send
    where 
        Self: Sized + Send,
    {
        async move {
            let data = tokio::fs::read(path)
                .await
                .map_err(|e| crate::CryptError::Io(format!("Failed to read file: {}", e)))?;
            Ok(self.with_data(data))
        }
    }
    
    /// Accept data from a string (UTF-8)
    fn with_text(self, text: &str) -> Self::Output
    where 
        Self: Sized,
    {
        self.with_data(text.as_bytes())
    }
    
    /// Accept data from base64 encoded string
    fn with_data_base64(self, data: &str) -> crate::Result<Self::Output>
    where 
        Self: Sized,
    {
        use base64::Engine;
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(data)?;
        Ok(self.with_data(decoded))
    }
    
    /// Accept data from hex encoded string
    fn with_data_hex(self, data: &str) -> crate::Result<Self::Output>
    where 
        Self: Sized,
    {
        let decoded = hex::decode(data)?;
        Ok(self.with_data(decoded))
    }
}

/// Builder that can accept ciphertext
pub trait CiphertextBuilder {
    type Output;
    fn with_ciphertext<T: Into<Vec<u8>>>(self, ciphertext: T) -> Self::Output;
    
    /// Accept ciphertext from a file
    fn with_ciphertext_file<P: AsRef<std::path::Path> + Send>(self, path: P) -> impl std::future::Future<Output = crate::Result<Self::Output>> + Send
    where 
        Self: Sized + Send,
    {
        async move {
            let data = tokio::fs::read(path)
                .await
                .map_err(|e| crate::CryptError::Io(format!("Failed to read ciphertext file: {}", e)))?;
            Ok(self.with_ciphertext(data))
        }
    }
    
    /// Accept ciphertext from base64 encoded string
    fn with_ciphertext_base64(self, ciphertext: &str) -> crate::Result<Self::Output> 
    where 
        Self: Sized,
    {
        use base64::Engine;
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(ciphertext)?;
        Ok(self.with_ciphertext(decoded))
    }
    
    /// Accept ciphertext from hex encoded string
    fn with_ciphertext_hex(self, ciphertext: &str) -> crate::Result<Self::Output>
    where 
        Self: Sized,
    {
        let decoded = hex::decode(ciphertext)?;
        Ok(self.with_ciphertext(decoded))
    }
}

/// Final stage builder that can encrypt
pub trait EncryptBuilder {
    fn encrypt(self) -> impl AsyncEncryptionResult;
}

/// Final stage builder that can decrypt
pub trait DecryptBuilder {
    fn decrypt(self) -> impl AsyncDecryptionResult;
}

/// Extension trait for encryption second pass
pub trait EncryptSecondPass: EncryptBuilder + Sized {
    fn second_pass<C>(self, second_cipher: C) -> TwoPassEncryptWrapper<Self, C> {
        TwoPassEncryptWrapper {
            first: self,
            second: second_cipher,
        }
    }
}

/// Extension trait for decryption second pass
pub trait DecryptSecondPass: DecryptBuilder + Sized {
    fn second_pass<C>(self, second_cipher: C) -> TwoPassDecryptWrapper<Self, C> {
        TwoPassDecryptWrapper {
            first: self,
            second: second_cipher,
        }
    }
}

// Blanket implementations
impl<T: EncryptBuilder + Sized> EncryptSecondPass for T {}
impl<T: DecryptBuilder + Sized> DecryptSecondPass for T {}

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
pub trait WithCompression: Sized {
    fn with_compression<C>(self, compression: C) -> CompressionWrapper<Self, C> {
        CompressionWrapper {
            cipher: self,
            compression,
        }
    }
}

// Blanket implementation for any type that has a key configured
impl<T: Sized> WithCompression for T {}

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

pub struct CompressionDataWrapper<CipherWithData, Compression> {
    cipher_with_data: CipherWithData,
    compression: Compression,
}

// Specific implementation for AES with compression
impl<Compression> EncryptBuilder
    for CompressionDataWrapper<super::aes_builder::AesWithKeyAndData, Compression>
where
    Compression: crate::compression::api::DataBuilder + Send + 'static,
    <Compression as crate::compression::api::DataBuilder>::Output:
        crate::compression::api::CompressExecutor + Send + 'static,
{
    fn encrypt(self) -> impl AsyncEncryptionResult {
        async move {
            // Compress the data first
            use crate::compression::api::CompressExecutor;
            let compressed_data = self
                .compression
                .with_data(self.cipher_with_data.data.clone())
                .compress()
                .await?;

            // Create new AES builder with compressed data and encrypt
            super::aes_builder::AesWithKeyAndData {
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
    for CompressionDataWrapper<super::chacha_builder::ChaChaWithKeyAndData, Compression>
where
    Compression: crate::compression::api::DataBuilder + Send + 'static,
    <Compression as crate::compression::api::DataBuilder>::Output:
        crate::compression::api::CompressExecutor + Send + 'static,
{
    fn encrypt(self) -> impl AsyncEncryptionResult {
        async move {
            // Compress the data first
            use crate::compression::api::CompressExecutor;
            let compressed_data = self
                .compression
                .with_data(self.cipher_with_data.data.clone())
                .compress()
                .await?;

            // Create new ChaCha builder with compressed data and encrypt
            super::chacha_builder::ChaChaWithKeyAndData {
                key_builder: self.cipher_with_data.key_builder,
                data: compressed_data,
            }
            .encrypt()
            .await
        }
    }
}

pub struct CompressionCiphertextWrapper<CipherWithCiphertext, Compression> {
    cipher_with_ciphertext: CipherWithCiphertext,
    compression: Compression,
}

// Specific implementation for AES with decompression
impl<Compression> DecryptBuilder
    for CompressionCiphertextWrapper<super::aes_builder::AesWithKeyAndCiphertext, Compression>
where
    Compression: crate::compression::api::DataBuilder + Send + 'static,
    <Compression as crate::compression::api::DataBuilder>::Output:
        crate::compression::api::DecompressExecutor + Send + 'static,
{
    fn decrypt(self) -> impl AsyncDecryptionResult {
        async move {
            // Decrypt first
            let decrypted_data = self.cipher_with_ciphertext.decrypt().await?;

            // Then decompress
            use crate::compression::api::DecompressExecutor;
            self.compression
                .with_data(decrypted_data)
                .decompress()
                .await
        }
    }
}

// Specific implementation for ChaCha with decompression
impl<Compression> DecryptBuilder
    for CompressionCiphertextWrapper<super::chacha_builder::ChaChaWithKeyAndCiphertext, Compression>
where
    Compression: crate::compression::api::DataBuilder + Send + 'static,
    <Compression as crate::compression::api::DataBuilder>::Output:
        crate::compression::api::DecompressExecutor + Send + 'static,
{
    fn decrypt(self) -> impl AsyncDecryptionResult {
        async move {
            // Decrypt first
            let decrypted_data = self.cipher_with_ciphertext.decrypt().await?;

            // Then decompress
            use crate::compression::api::DecompressExecutor;
            self.compression
                .with_data(decrypted_data)
                .decompress()
                .await
        }
    }
}
