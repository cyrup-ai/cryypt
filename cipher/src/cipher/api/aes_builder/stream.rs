//! AES streaming operations
//!
//! Contains stream-based encryption and decryption implementations.

use super::AesWithKey;
use super::super::{CipherOnResultExt, CipherProducer, CryptoStream};
use crate::{CryptError, Result};
use aes_gcm::{
    aead::{generic_array::GenericArray, Aead, KeyInit},
    Aes256Gcm,
};
use rand::RngCore;
use zeroize::Zeroizing;
use std::pin::Pin;
use std::future::Future;

impl AesWithKey {
    /// Handle chunks with the on_chunk! macro - README.md pattern
    /// This stores the handler for use in encrypt_stream/decrypt_stream
    pub fn on_chunk<F>(mut self, handler: F) -> Self 
    where
        F: Fn(Result<Vec<u8>>) -> Option<Vec<u8>> + Send + Sync + 'static,
    {
        self.chunk_handler = Some(Box::new(handler));
        self
    }

    /// Encrypt a stream of data - README.md pattern
    /// This enables: cipher.aes().with_key(key).encrypt_stream(input_stream)
    pub fn encrypt_stream<S>(self, input_stream: S) -> CryptoStream
    where
        S: tokio_stream::Stream<Item = Vec<u8>> + Send + 'static,
    {
        use tokio_stream::StreamExt;
        
        let (tx, rx) = tokio::sync::mpsc::channel(100);
        let key_builder = self.key_builder;
        let chunk_handler = self.chunk_handler;
        
        tokio::spawn(async move {
            // First resolve the key once
            let key_result = key_builder.resolve().await;
            let key_vec = match key_result {
                Ok(k) => k,
                Err(e) => {
                    let _ = tx.send(Err(CryptError::from(e))).await;
                    return;
                }
            };
            
            // Create secure key wrapper
            let key_bytes = Zeroizing::new(key_vec);
            
            // Validate key size for AES-256
            if key_bytes.len() != 32 {
                let _ = tx.send(Err(CryptError::InvalidKeySize {
                    expected: 32,
                    actual: key_bytes.len(),
                })).await;
                return;
            }
            
            // Create AES-256-GCM cipher instance
            let key = GenericArray::from_slice(&key_bytes);
            let cipher = Aes256Gcm::new(key);
            
            // Process each chunk from the input stream
            let mut stream = Box::pin(input_stream);
            while let Some(chunk) = stream.next().await {
                // Generate a new nonce for each chunk
                let mut nonce_bytes = vec![0u8; 12];
                rand::rng().fill_bytes(&mut nonce_bytes);
                let nonce = GenericArray::from_slice(&nonce_bytes);
                
                // Encrypt the chunk
                let ciphertext = match cipher.encrypt(nonce, chunk.as_ref()) {
                    Ok(ct) => ct,
                    Err(_) => {
                        let _ = tx.send(Err(CryptError::EncryptionFailed("AES-GCM encryption failed".to_string()))).await;
                        continue;
                    }
                };
                
                // Build result: nonce || ciphertext
                let mut result = Vec::with_capacity(nonce_bytes.len() + ciphertext.len());
                result.extend_from_slice(&nonce_bytes);
                result.extend_from_slice(&ciphertext);
                
                // Apply chunk handler if present, otherwise send directly
                let final_chunk = if let Some(ref handler) = chunk_handler {
                    match handler(Ok(result)) {
                        Some(chunk) => chunk,
                        None => continue, // Handler filtered out this chunk
                    }
                } else {
                    result
                };
                
                // Send the processed chunk
                if tx.send(Ok(final_chunk)).await.is_err() {
                    // Receiver dropped
                    break;
                }
            }
        });
        
        CryptoStream::new(rx)
    }

    /// Decrypt a stream of data - README.md pattern
    /// This enables: cipher.aes().with_key(key).decrypt_stream(encrypted_stream)
    pub fn decrypt_stream<S>(self, encrypted_stream: S) -> CryptoStream
    where
        S: tokio_stream::Stream<Item = Vec<u8>> + Send + 'static,
    {
        use tokio_stream::StreamExt;
        
        let (tx, rx) = tokio::sync::mpsc::channel(100);
        let key_builder = self.key_builder;
        let chunk_handler = self.chunk_handler;
        
        tokio::spawn(async move {
            // First resolve the key once
            let key_result = key_builder.resolve().await;
            let key_vec = match key_result {
                Ok(k) => k,
                Err(e) => {
                    let _ = tx.send(Err(CryptError::from(e))).await;
                    return;
                }
            };
            
            // Create secure key wrapper
            let key_bytes = Zeroizing::new(key_vec);
            
            // Validate key size for AES-256
            if key_bytes.len() != 32 {
                let _ = tx.send(Err(CryptError::InvalidKeySize {
                    expected: 32,
                    actual: key_bytes.len(),
                })).await;
                return;
            }
            
            // Create AES-256-GCM cipher instance
            let key = GenericArray::from_slice(&key_bytes);
            let cipher = Aes256Gcm::new(key);
            
            // Process each chunk from the encrypted stream
            let mut stream = Box::pin(encrypted_stream);
            while let Some(chunk) = stream.next().await {
                // Extract nonce and ciphertext
                if chunk.len() < 12 {
                    let _ = tx.send(Err(CryptError::DecryptionFailed("Chunk too short".to_string()))).await;
                    continue;
                }
                
                let (nonce_bytes, cipher_data) = chunk.split_at(12);
                let nonce = GenericArray::from_slice(nonce_bytes);
                
                // Decrypt the chunk
                let plaintext = match cipher.decrypt(nonce, cipher_data) {
                    Ok(pt) => pt,
                    Err(_) => {
                        let _ = tx.send(Err(CryptError::DecryptionFailed("AES-GCM decryption failed".to_string()))).await;
                        continue;
                    }
                };
                
                // Apply chunk handler if present, otherwise send directly
                let final_chunk = if let Some(ref handler) = chunk_handler {
                    match handler(Ok(plaintext)) {
                        Some(chunk) => chunk,
                        None => continue, // Handler filtered out this chunk
                    }
                } else {
                    plaintext
                };
                
                // Send the processed chunk
                if tx.send(Ok(final_chunk)).await.is_err() {
                    // Receiver dropped
                    break;
                }
            }
        });
        
        CryptoStream::new(rx)
    }
}

// Implement CipherOnResultExt for AesWithKey to support on_result! macro
impl CipherOnResultExt for AesWithKey {
    type EncryptOutput = Result<Vec<u8>>;
    type DecryptOutput = Result<Vec<u8>>;
    type EncryptFuture = Pin<Box<dyn Future<Output = Result<Vec<u8>>> + Send>>;
    type DecryptFuture = Pin<Box<dyn Future<Output = Result<Vec<u8>>> + Send>>;
    
    fn encrypt<T: Into<Vec<u8>> + Send + 'static>(self, data: T) -> Self::EncryptFuture {
        Box::pin(self.encrypt(data))
    }
    
    fn decrypt(self, ciphertext: &[u8]) -> Self::DecryptFuture {
        let ciphertext = ciphertext.to_vec();
        Box::pin(async move { self.decrypt(&ciphertext).await })
    }
}

// Implement CipherProducer for AesWithKey to support on_result! macro
impl CipherProducer for AesWithKey {
    async fn produce_encrypt(self, data: Vec<u8>) -> Result<Vec<u8>> {
        self.encrypt(data).await
    }
    
    async fn produce_decrypt(self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        self.decrypt(ciphertext).await
    }
}