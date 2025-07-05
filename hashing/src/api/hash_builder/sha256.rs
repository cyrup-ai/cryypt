//! SHA-256 hash implementation

use super::super::{
    hash::Sha256Hash,
    HasSalt, NoData, NoSalt,
};
use super::{HashBuilder, HashStream, HashAlgorithm};
use super::stream::DynHasher;
use crate::{HashResult, Result};
use tokio_stream::Stream;
use crate::hash_on_result_impl;

// SHA-256 compute methods without key
impl<P> HashBuilder<Sha256Hash, NoData, NoSalt, P> {
    /// Compute hash of the provided data
    pub async fn compute<T: Into<Vec<u8>>>(self, data: T) -> Result<HashResult> {
        let data = data.into();
        let result = sha256_hash(data, None, 1).await.map(HashResult::from);
        
        if let Some(handler) = self.result_handler {
            handler(result)
        } else {
            result
        }
    }
    
    /// Compute hash from a stream of data
    pub fn compute_stream<S: Stream<Item = Vec<u8>> + Send + 'static>(
        self, 
        stream: S
    ) -> HashStream {
        HashStream::new(stream, HashAlgorithm::Sha256, self.chunk_handler)
    }
}

// SHA-256 compute methods with key (HMAC)
impl<P> HashBuilder<Sha256Hash, NoData, HasSalt, P> {
    /// Compute HMAC of the provided data
    pub async fn compute<T: Into<Vec<u8>>>(self, data: T) -> Result<HashResult> {
        let data = data.into();
        let result = sha256_hmac(data, self.salt.0).await.map(HashResult::from);
        
        if let Some(handler) = self.result_handler {
            handler(result)
        } else {
            result
        }
    }
    
    /// Compute HMAC from a stream of data
    pub fn compute_stream<S: Stream<Item = Vec<u8>> + Send + 'static>(
        self, 
        stream: S
    ) -> HashStream {
        // TODO: Implement streaming HMAC
        HashStream::new(stream, HashAlgorithm::Sha256, self.chunk_handler)
    }
}

// SHA-256 hasher
pub(super) struct Sha256Hasher(sha2::Sha256);

impl Sha256Hasher {
    pub(super) fn new() -> Self {
        use sha2::{Digest, Sha256};
        Self(Sha256::new())
    }
}

impl DynHasher for Sha256Hasher {
    fn update(&mut self, data: &[u8]) {
        use sha2::Digest;
        self.0.update(data);
    }
    
    fn clone_finalize(&self) -> Vec<u8> {
        use sha2::Digest;
        self.0.clone().finalize().to_vec()
    }
    
    fn finalize(self: Box<Self>) -> Vec<u8> {
        use sha2::Digest;
        self.0.finalize().to_vec()
    }
}

// SHA-256 hash function
pub(super) async fn sha256_hash(data: Vec<u8>, salt: Option<Vec<u8>>, passes: u32) -> Result<Vec<u8>> {
    use sha2::{Digest, Sha256};

    let mut input = data;
    if let Some(salt) = salt {
        input.extend_from_slice(&salt);
    }

    let mut result = input.clone();
    for _ in 0..passes {
        let mut hasher = Sha256::new();
        hasher.update(&result);
        result = hasher.finalize().to_vec();
    }

    Ok(result)
}

/// Apply result handler using hash_on_result_impl macro
pub(crate) fn apply_hash_result_handler() -> impl Fn(Result<Vec<u8>>) -> Result<Vec<u8>> {
    hash_on_result_impl!(|result| { Ok => Ok(result), Err(e) => Err(e) })
}

// SHA-256 HMAC function
pub(super) async fn sha256_hmac(data: Vec<u8>, key: Vec<u8>) -> Result<Vec<u8>> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    
    type HmacSha256 = Hmac<Sha256>;
    
    let mut mac = HmacSha256::new_from_slice(&key)
        .map_err(|e| crate::HashError::internal(format!("HMAC key error: {}", e)))?;
    mac.update(&data);
    Ok(mac.finalize().into_bytes().to_vec())
}