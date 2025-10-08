//! BLAKE2b hash implementation

use super::super::{
    hash::Blake2bHash,
    HasSalt, NoData, NoSalt,
};
use super::{HashBuilder, HashStream, HashAlgorithm};
use super::stream::DynHasher;
use crate::{HashResult, Result};
use tokio_stream::Stream;

// BLAKE2b compute methods without key
impl<P> HashBuilder<Blake2bHash, NoData, NoSalt, P> {
    /// Set output size for BLAKE2b
    pub fn with_output_size(mut self, size: u8) -> Self {
        self.hasher.output_size = size;
        self
    }
    
    /// Compute hash of the provided data
    /// Returns unwrapped Vec<u8> with default error handling (empty Vec on error)
    pub async fn compute<T: Into<Vec<u8>>>(self, data: T) -> Vec<u8> {
        let data = data.into();
        let result = blake2b_hash(data, None, self.hasher.output_size).await.map(HashResult::from);
        
        if let Some(handler) = self.result_handler {
            // User provided handler: give them Result<HashResult>, get back Vec<u8>
            (*handler)(result)
        } else {
            // Default unwrapping: Ok(hash_result) => hash_result.to_vec(), Err(_) => Vec::new()
            match result {
                Ok(hash_result) => hash_result.to_vec(),
                Err(_) => Vec::new(),
            }
        }
    }
    
    /// Compute hash from a stream of data
    pub fn compute_stream<S: Stream<Item = Vec<u8>> + Send + 'static>(
        self, 
        stream: S
    ) -> HashStream {
        HashStream::new(stream, HashAlgorithm::Blake2b(self.hasher.output_size), self.chunk_handler)
    }
}

// BLAKE2b compute methods with key
impl<P> HashBuilder<Blake2bHash, NoData, HasSalt, P> {
    /// Set output size for BLAKE2b
    pub fn with_output_size(mut self, size: u8) -> Self {
        self.hasher.output_size = size;
        self
    }
    
    /// Compute hash of the provided data with key
    /// Returns unwrapped Vec<u8> with default error handling (empty Vec on error)
    pub async fn compute<T: Into<Vec<u8>>>(self, data: T) -> Vec<u8> {
        let data = data.into();
        let result = blake2b_hash(data, Some(self.salt.0), self.hasher.output_size).await.map(HashResult::from);
        
        if let Some(handler) = self.result_handler {
            // User provided handler: give them Result<HashResult>, get back Vec<u8>
            (*handler)(result)
        } else {
            // Default unwrapping: Ok(hash_result) => hash_result.to_vec(), Err(_) => Vec::new()
            match result {
                Ok(hash_result) => hash_result.to_vec(),
                Err(_) => Vec::new(),
            }
        }
    }
    
    /// Compute hash from a stream of data with key
    pub fn compute_stream<S: Stream<Item = Vec<u8>> + Send + 'static>(
        self, 
        stream: S
    ) -> HashStream {
        use blake2::{Blake2bMac512, digest::KeyInit, Mac};
        use tokio::sync::mpsc;
        
        let key = self.salt.0.clone();
        let output_size = self.hasher.output_size;
        let (sender, receiver) = mpsc::channel(100);
        let chunk_handler = self.chunk_handler;
        
        tokio::spawn(async move {
            use tokio_stream::StreamExt;
            use crate::error::{HashError, Result};
            let mut stream = Box::pin(stream);
            let mut mac = Blake2bMac512::new_from_slice(&key)
                .map_err(|e| HashError::MacInitialization(format!("Failed to initialize BLAKE2b MAC: {e}")))?;
            
            while let Some(chunk) = stream.next().await {
                mac.update(&chunk);
                // Send intermediate BLAKE2b MAC for progressive verification
                let intermediate = mac.clone().finalize().into_bytes();
                let truncated = intermediate[..output_size.min(64) as usize].to_vec();
                let _ = sender.send(Ok(truncated)).await;
            }
            
            // Final BLAKE2b MAC
            let final_mac = mac.finalize().into_bytes();
            let final_truncated = final_mac[..output_size.min(64) as usize].to_vec();
            let _ = sender.send(Ok(final_truncated)).await;
        });
        
        HashStream {
            receiver,
            handler: chunk_handler.map(|h| Box::new(h) as Box<dyn Fn(Result<Vec<u8>>) -> Option<Vec<u8>> + Send>),
        }
    }
}

// BLAKE2b hasher
pub(super) struct Blake2bHasher {
    pub(super) hasher: blake2::Blake2b512,
    pub(super) output_size: u8,
}

impl Blake2bHasher {
    pub(super) fn new(output_size: u8) -> Self {
        use blake2::{Blake2b512, Digest};
        Self {
            hasher: Blake2b512::new(),
            output_size,
        }
    }
}

impl DynHasher for Blake2bHasher {
    fn update(&mut self, data: &[u8]) {
        use blake2::Digest;
        self.hasher.update(data);
    }
    
    fn clone_finalize(&self) -> Vec<u8> {
        use blake2::Digest;
        let result = self.hasher.clone().finalize();
        result[..self.output_size.min(64) as usize].to_vec()
    }
    
    fn finalize(self: Box<Self>) -> Vec<u8> {
        use blake2::Digest;
        let result = self.hasher.finalize();
        result[..self.output_size.min(64) as usize].to_vec()
    }
}

// BLAKE2b hash function
pub(super) async fn blake2b_hash(data: Vec<u8>, key: Option<Vec<u8>>, output_size: u8) -> Result<Vec<u8>> {
    use blake2::digest::{Digest, KeyInit, Mac};
    use blake2::{Blake2b512, Blake2bMac512};

    if let Some(key) = key {
        // Use Blake2b as MAC
        let mut mac = <Blake2bMac512 as KeyInit>::new_from_slice(&key)
            .map_err(|e| crate::HashError::internal(format!("Blake2b key error: {e}")))?;
        mac.update(&data);
        let result = mac.finalize().into_bytes().to_vec();
        // Truncate to requested size
        Ok(result[..output_size.min(64) as usize].to_vec())
    } else {
        // Use Blake2b as hash
        let mut hasher = Blake2b512::default();
        hasher.update(&data);
        let result = hasher.finalize().to_vec();
        // Truncate to requested size
        Ok(result[..output_size.min(64) as usize].to_vec())
    }
}