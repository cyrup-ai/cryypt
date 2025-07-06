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
    pub async fn compute<T: Into<Vec<u8>>>(self, data: T) -> Result<HashResult> {
        let data = data.into();
        let hash_result = blake2b_hash(data, None, self.hasher.output_size).await?;
        
        if let Some(handler) = self.result_handler {
            handler(Ok(HashResult::from(hash_result)))
        } else {
            Ok(HashResult::from(hash_result))
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
    pub async fn compute<T: Into<Vec<u8>>>(self, data: T) -> Result<HashResult> {
        let data = data.into();
        let result = blake2b_hash(data, Some(self.salt.0), self.hasher.output_size).await.map(HashResult::from);
        
        if let Some(handler) = self.result_handler {
            handler(result)
        } else {
            result
        }
    }
    
    /// Compute hash from a stream of data with key
    pub fn compute_stream<S: Stream<Item = Vec<u8>> + Send + 'static>(
        self, 
        stream: S
    ) -> HashStream {
        // TODO: Implement streaming BLAKE2b with key
        HashStream::new(stream, HashAlgorithm::Blake2b(self.hasher.output_size), self.chunk_handler)
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
            .map_err(|e| crate::HashError::internal(format!("Blake2b key error: {}", e)))?;
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