//! SHA3 hash implementation (256, 384, 512 variants)

use super::super::{
    hash::{Sha3_256Hash, Sha3_384Hash, Sha3_512Hash},
    HasSalt, NoData, NoSalt,
};
use super::{HashBuilder, HashStream, HashAlgorithm};
use super::stream::DynHasher;
use crate::{HashResult, Result};
use tokio_stream::Stream;
use crate::hash_on_result_impl;

// SHA3-256 compute methods without key
impl<P> HashBuilder<Sha3_256Hash, NoData, NoSalt, P> {
    /// Compute hash of the provided data
    pub async fn compute<T: Into<Vec<u8>>>(self, data: T) -> Result<HashResult> {
        let data = data.into();
        let result = sha3_256_hash(data, None, 1).await.map(HashResult::from);
        
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
        HashStream::new(stream, HashAlgorithm::Sha3_256, self.chunk_handler)
    }
}

// SHA3-256 compute methods with key (HMAC)
impl<P> HashBuilder<Sha3_256Hash, NoData, HasSalt, P> {
    /// Compute HMAC of the provided data
    pub async fn compute<T: Into<Vec<u8>>>(self, data: T) -> Result<HashResult> {
        let data = data.into();
        let result = sha3_256_hmac(data, self.salt.0).await.map(HashResult::from);
        
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
        HashStream::new(stream, HashAlgorithm::Sha3_256, self.chunk_handler)
    }
}

// SHA3-384 compute methods without key
impl<P> HashBuilder<Sha3_384Hash, NoData, NoSalt, P> {
    /// Compute hash of the provided data
    pub async fn compute<T: Into<Vec<u8>>>(self, data: T) -> Result<HashResult> {
        let data = data.into();
        let result = sha3_384_hash(data, None, 1).await.map(HashResult::from);
        
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
        HashStream::new(stream, HashAlgorithm::Sha3_384, self.chunk_handler)
    }
}

// SHA3-384 compute methods with key (HMAC)
impl<P> HashBuilder<Sha3_384Hash, NoData, HasSalt, P> {
    /// Compute HMAC of the provided data
    pub async fn compute<T: Into<Vec<u8>>>(self, data: T) -> Result<HashResult> {
        let data = data.into();
        let result = sha3_384_hmac(data, self.salt.0).await.map(HashResult::from);
        
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
        HashStream::new(stream, HashAlgorithm::Sha3_384, self.chunk_handler)
    }
}

// SHA3-512 compute methods without key
impl<P> HashBuilder<Sha3_512Hash, NoData, NoSalt, P> {
    /// Compute hash of the provided data
    pub async fn compute<T: Into<Vec<u8>>>(self, data: T) -> Result<HashResult> {
        let data = data.into();
        let result = sha3_512_hash(data, None, 1).await.map(HashResult::from);
        
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
        HashStream::new(stream, HashAlgorithm::Sha3_512, self.chunk_handler)
    }
}

// SHA3-512 compute methods with key (HMAC)
impl<P> HashBuilder<Sha3_512Hash, NoData, HasSalt, P> {
    /// Compute HMAC of the provided data
    pub async fn compute<T: Into<Vec<u8>>>(self, data: T) -> Result<HashResult> {
        let data = data.into();
        let result = sha3_512_hmac(data, self.salt.0).await.map(HashResult::from);
        
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
        HashStream::new(stream, HashAlgorithm::Sha3_512, self.chunk_handler)
    }
}

// SHA3 hashers
pub(super) struct Sha3_256Hasher(sha3::Sha3_256);
pub(super) struct Sha3_384Hasher(sha3::Sha3_384);
pub(super) struct Sha3_512Hasher(sha3::Sha3_512);

impl Sha3_256Hasher {
    pub(super) fn new() -> Self {
        use sha3::{Digest, Sha3_256};
        Self(Sha3_256::new())
    }
}

impl DynHasher for Sha3_256Hasher {
    fn update(&mut self, data: &[u8]) {
        use sha3::Digest;
        self.0.update(data);
    }
    
    fn clone_finalize(&self) -> Vec<u8> {
        use sha3::Digest;
        self.0.clone().finalize().to_vec()
    }
    
    fn finalize(self: Box<Self>) -> Vec<u8> {
        use sha3::Digest;
        self.0.finalize().to_vec()
    }
}

impl Sha3_384Hasher {
    pub(super) fn new() -> Self {
        use sha3::{Digest, Sha3_384};
        Self(Sha3_384::new())
    }
}

impl DynHasher for Sha3_384Hasher {
    fn update(&mut self, data: &[u8]) {
        use sha3::Digest;
        self.0.update(data);
    }
    
    fn clone_finalize(&self) -> Vec<u8> {
        use sha3::Digest;
        self.0.clone().finalize().to_vec()
    }
    
    fn finalize(self: Box<Self>) -> Vec<u8> {
        use sha3::Digest;
        self.0.finalize().to_vec()
    }
}

impl Sha3_512Hasher {
    pub(super) fn new() -> Self {
        use sha3::{Digest, Sha3_512};
        Self(Sha3_512::new())
    }
}

impl DynHasher for Sha3_512Hasher {
    fn update(&mut self, data: &[u8]) {
        use sha3::Digest;
        self.0.update(data);
    }
    
    fn clone_finalize(&self) -> Vec<u8> {
        use sha3::Digest;
        self.0.clone().finalize().to_vec()
    }
    
    fn finalize(self: Box<Self>) -> Vec<u8> {
        use sha3::Digest;
        self.0.finalize().to_vec()
    }
}

// SHA3 hash functions
pub(super) async fn sha3_256_hash(data: Vec<u8>, salt: Option<Vec<u8>>, passes: u32) -> Result<Vec<u8>> {
    use sha3::{Digest, Sha3_256};

    let mut input = data;
    if let Some(salt) = salt {
        input.extend_from_slice(&salt);
    }

    let mut result = input.clone();
    for _ in 0..passes {
        let mut hasher = Sha3_256::new();
        hasher.update(&result);
        result = hasher.finalize().to_vec();
    }

    Ok(result)
}

pub(super) async fn sha3_256_hmac(data: Vec<u8>, key: Vec<u8>) -> Result<Vec<u8>> {
    use hmac::{Hmac, Mac};
    use sha3::Sha3_256;
    
    type HmacSha3_256 = Hmac<Sha3_256>;
    
    let mut mac = HmacSha3_256::new_from_slice(&key)
        .map_err(|e| crate::HashError::internal(format!("HMAC key error: {}", e)))?;
    mac.update(&data);
    Ok(mac.finalize().into_bytes().to_vec())
}

pub(super) async fn sha3_384_hash(data: Vec<u8>, salt: Option<Vec<u8>>, iterations: u32) -> Result<Vec<u8>> {
    use sha3::{Digest, Sha3_384};

    let mut input = data;
    if let Some(salt) = salt {
        input.extend_from_slice(&salt);
    }

    let mut result = input;
    for _ in 0..iterations {
        let mut hasher = Sha3_384::new();
        hasher.update(&result);
        result = hasher.finalize().to_vec();
    }

    Ok(result)
}

pub(super) async fn sha3_384_hmac(data: Vec<u8>, key: Vec<u8>) -> Result<Vec<u8>> {
    use hmac::{Hmac, Mac};
    use sha3::Sha3_384;
    
    type HmacSha3_384 = Hmac<Sha3_384>;
    
    let mut mac = HmacSha3_384::new_from_slice(&key)
        .map_err(|e| crate::HashError::internal(format!("HMAC key error: {}", e)))?;
    mac.update(&data);
    Ok(mac.finalize().into_bytes().to_vec())
}

pub(super) async fn sha3_512_hash(data: Vec<u8>, salt: Option<Vec<u8>>, iterations: u32) -> Result<Vec<u8>> {
    use sha3::{Digest, Sha3_512};

    let mut input = data;
    if let Some(salt) = salt {
        input.extend_from_slice(&salt);
    }

    let mut result = input;
    for _ in 0..iterations {
        let mut hasher = Sha3_512::new();
        hasher.update(&result);
        result = hasher.finalize().to_vec();
    }

    Ok(result)
}

pub(super) async fn sha3_512_hmac(data: Vec<u8>, key: Vec<u8>) -> Result<Vec<u8>> {
    use hmac::{Hmac, Mac};
    use sha3::Sha3_512;
    
    type HmacSha3_512 = Hmac<Sha3_512>;
    
    let mut mac = HmacSha3_512::new_from_slice(&key)
        .map_err(|e| crate::HashError::internal(format!("HMAC key error: {}", e)))?;
    mac.update(&data);
    Ok(mac.finalize().into_bytes().to_vec())
}