//! Builder for hash operations

use super::super::hash_result::HashResultImpl;
use super::{
    NoData, HasData, NoSalt, HasSalt, NoPasses, HasPasses,
    hash::{Sha256Hash, Sha3_256Hash, Sha3_384Hash, Sha3_512Hash, Blake2bHash},
    passes::HashPasses,
};

/// Builder for hash operations
pub struct HashBuilder<H, D, S, P> {
    pub(super) hasher: H,
    pub(super) data: D,
    pub(super) salt: S,
    pub(super) passes: P,
}

// Methods for adding data
impl<H, S, P> HashBuilder<H, NoData, S, P> {
    /// Set the data to hash (as text)
    pub fn with_text<T: Into<String>>(self, text: T) -> HashBuilder<H, HasData<Vec<u8>>, S, P> {
        HashBuilder {
            hasher: self.hasher,
            data: HasData(text.into().into_bytes()),
            salt: self.salt,
            passes: self.passes,
        }
    }
    
    /// Set the data to hash (as bytes)
    pub fn with_data<T: Into<Vec<u8>>>(self, data: T) -> HashBuilder<H, HasData<Vec<u8>>, S, P> {
        HashBuilder {
            hasher: self.hasher,
            data: HasData(data.into()),
            salt: self.salt,
            passes: self.passes,
        }
    }
}

// Methods for adding salt
impl<H, D, P> HashBuilder<H, D, NoSalt, P> {
    /// Set the salt for hashing
    pub fn with_salt<T: Into<Vec<u8>>>(self, salt: T) -> HashBuilder<H, D, HasSalt, P> {
        HashBuilder {
            hasher: self.hasher,
            data: self.data,
            salt: HasSalt(salt.into()),
            passes: self.passes,
        }
    }
}

// Methods for setting passes (for iterative hashing)
impl<H, D, S> HashBuilder<H, D, S, NoPasses> {
    /// Set the number of passes for iterative hashing
    pub fn with_passes(self, passes: HashPasses) -> HashBuilder<H, D, S, HasPasses> {
        HashBuilder {
            hasher: self.hasher,
            data: self.data,
            salt: self.salt,
            passes: HasPasses(passes),
        }
    }
}

// Hash implementations for different algorithms
trait HashImpl {
    fn hash_data(&self, data: Vec<u8>, salt: Option<Vec<u8>>, passes: u32) -> HashResultImpl;
}

// SHA-256 with data only
impl HashBuilder<Sha256Hash, HasData<Vec<u8>>, NoSalt, NoPasses> {
    pub fn hash(self) -> impl AsyncHashResult {
        sha256_hash(self.data.0, None, 1)
    }
}

// SHA-256 with data and salt
impl HashBuilder<Sha256Hash, HasData<Vec<u8>>, HasSalt, NoPasses> {
    pub fn hash(self) -> impl AsyncHashResult {
        sha256_hash(self.data.0, Some(self.salt.0), 1)
    }
}

// SHA-256 with data and passes
impl HashBuilder<Sha256Hash, HasData<Vec<u8>>, NoSalt, HasPasses> {
    pub fn hash(self) -> impl AsyncHashResult {
        sha256_hash(self.data.0, None, self.passes.0.iterations())
    }
}

// SHA-256 with all options
impl HashBuilder<Sha256Hash, HasData<Vec<u8>>, HasSalt, HasPasses> {
    pub fn hash(self) -> impl AsyncHashResult {
        sha256_hash(self.data.0, Some(self.salt.0), self.passes.0.iterations())
    }
}

// SHA3-256 implementations
impl HashBuilder<Sha3_256Hash, HasData<Vec<u8>>, NoSalt, NoPasses> {
    pub fn hash(self) -> impl AsyncHashResult {
        sha3_256_hash(self.data.0, None, 1)
    }
}

impl HashBuilder<Sha3_256Hash, HasData<Vec<u8>>, HasSalt, NoPasses> {
    pub fn hash(self) -> impl AsyncHashResult {
        sha3_256_hash(self.data.0, Some(self.salt.0), 1)
    }
}

impl HashBuilder<Sha3_256Hash, HasData<Vec<u8>>, NoSalt, HasPasses> {
    pub fn hash(self) -> impl AsyncHashResult {
        sha3_256_hash(self.data.0, None, self.passes.0.iterations())
    }
}

impl HashBuilder<Sha3_256Hash, HasData<Vec<u8>>, HasSalt, HasPasses> {
    pub fn hash(self) -> impl AsyncHashResult {
        sha3_256_hash(self.data.0, Some(self.salt.0), self.passes.0.iterations())
    }
}

// Blake2b implementations
impl HashBuilder<Blake2bHash, HasData<Vec<u8>>, NoSalt, NoPasses> {
    pub fn hash(self) -> impl AsyncHashResult {
        blake2b_hash(self.data.0, None, self.hasher.output_size)
    }
}

impl HashBuilder<Blake2bHash, HasData<Vec<u8>>, HasSalt, NoPasses> {
    pub fn hash(self) -> impl AsyncHashResult {
        blake2b_hash(self.data.0, Some(self.salt.0), self.hasher.output_size)
    }
}

// Trait for async hash results
use crate::Result;
use std::future::Future;

pub trait AsyncHashResult: Future<Output = Result<Vec<u8>>> + Send {}
impl<T> AsyncHashResult for T where T: Future<Output = Result<Vec<u8>>> + Send {}

// Internal hash functions that return HashResultImpl
fn sha256_hash(data: Vec<u8>, salt: Option<Vec<u8>>, passes: u32) -> HashResultImpl {
    HashResultImpl::from_computation(move || {
        use sha2::{Sha256, Digest};
        
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
    })
}

fn sha3_256_hash(data: Vec<u8>, salt: Option<Vec<u8>>, passes: u32) -> HashResultImpl {
    HashResultImpl::from_computation(move || {
        use sha3::{Sha3_256, Digest};
        
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
    })
}

fn blake2b_hash(data: Vec<u8>, key: Option<Vec<u8>>, output_size: u8) -> HashResultImpl {
    HashResultImpl::from_computation(move || {
        use blake2::{Blake2b512, Blake2bMac512};
        use blake2::digest::{Digest, KeyInit, Mac};
        
        if let Some(key) = key {
            // Use Blake2b as MAC
            let mut mac = <Blake2bMac512 as KeyInit>::new_from_slice(&key)
                .map_err(|e| crate::CryptError::internal(format!("Blake2b key error: {}", e)))?;
            mac.update(&data);
            Ok(mac.finalize().into_bytes().to_vec())
        } else {
            // Use Blake2b as hash
            let mut hasher = Blake2b512::default();
            hasher.update(&data);
            Ok(hasher.finalize().to_vec())
        }
    })
}