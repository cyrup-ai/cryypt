//! Entry point for the fluent hashing API following README.md patterns exactly

use crate::{Result, HashResult};

/// Entry point for hash operations - README.md pattern
pub struct Hash;

impl Hash {
    /// Use SHA-256 - README.md pattern
    pub fn sha256() -> Sha256Builder {
        Sha256Builder::new()
    }

    /// Use SHA3-256 - README.md pattern  
    pub fn sha3_256() -> Sha3_256Builder {
        Sha3_256Builder::new()
    }

    /// Use Blake2b - README.md pattern
    pub fn blake2b() -> Blake2bBuilder {
        Blake2bBuilder::new()
    }
}

/// SHA-256 hash builder following README.md patterns
pub struct Sha256Builder {
    result_handler: Option<Box<dyn Fn(Result<HashResult>) -> Result<HashResult> + Send + Sync>>,
}

impl Sha256Builder {
    /// Create new SHA-256 builder
    pub fn new() -> Self {
        Self {
            result_handler: None,
        }
    }

    /// Add on_result! handler - README.md pattern
    pub fn on_result<F>(mut self, handler: F) -> Self
    where
        F: Fn(Result<HashResult>) -> Result<HashResult> + Send + Sync + 'static,
    {
        self.result_handler = Some(Box::new(handler));
        self
    }

    /// Compute hash - action takes data as argument per README.md
    pub async fn compute<T: Into<Vec<u8>>>(self, data: T) -> Result<HashResult> {
        let data = data.into();
        
        let result = sha256_hash(&data).await;
        
        if let Some(handler) = self.result_handler {
            handler(result)
        } else {
            result
        }
    }
}

/// SHA3-256 hash builder following README.md patterns
pub struct Sha3_256Builder {
    result_handler: Option<Box<dyn Fn(Result<HashResult>) -> Result<HashResult> + Send + Sync>>,
}

impl Sha3_256Builder {
    /// Create new SHA3-256 builder
    pub fn new() -> Self {
        Self {
            result_handler: None,
        }
    }

    /// Add on_result! handler - README.md pattern
    pub fn on_result<F>(mut self, handler: F) -> Self
    where
        F: Fn(Result<HashResult>) -> Result<HashResult> + Send + Sync + 'static,
    {
        self.result_handler = Some(Box::new(handler));
        self
    }

    /// Compute hash - action takes data as argument per README.md
    pub async fn compute<T: Into<Vec<u8>>>(self, data: T) -> Result<HashResult> {
        let data = data.into();
        
        let result = sha3_256_hash(&data).await;
        
        if let Some(handler) = self.result_handler {
            handler(result)
        } else {
            result
        }
    }
}

/// Blake2b hash builder following README.md patterns
pub struct Blake2bBuilder {
    result_handler: Option<Box<dyn Fn(Result<HashResult>) -> Result<HashResult> + Send + Sync>>,
}

impl Blake2bBuilder {
    /// Create new Blake2b builder
    pub fn new() -> Self {
        Self {
            result_handler: None,
        }
    }

    /// Add on_result! handler - README.md pattern
    pub fn on_result<F>(mut self, handler: F) -> Self
    where
        F: Fn(Result<HashResult>) -> Result<HashResult> + Send + Sync + 'static,
    {
        self.result_handler = Some(Box::new(handler));
        self
    }

    /// Compute hash - action takes data as argument per README.md
    pub async fn compute<T: Into<Vec<u8>>>(self, data: T) -> Result<HashResult> {
        let data = data.into();
        
        let result = blake2b_hash(&data).await;
        
        if let Some(handler) = self.result_handler {
            handler(result)
        } else {
            result
        }
    }
}

// Internal hash functions using true async
async fn sha256_hash(data: &[u8]) -> Result<HashResult> {
    let data = data.to_vec();
    
    tokio::task::spawn_blocking(move || {
        use sha2::{Sha256, Digest};
        
        let mut hasher = Sha256::new();
        hasher.update(&data);
        let result = hasher.finalize();
        
        Ok(HashResult::new(result.to_vec()))
    })
    .await
    .map_err(|e| crate::HashError::internal(e.to_string()))?
}

async fn sha3_256_hash(data: &[u8]) -> Result<HashResult> {
    let data = data.to_vec();
    
    tokio::task::spawn_blocking(move || {
        use sha3::{Sha3_256, Digest};
        
        let mut hasher = Sha3_256::new();
        hasher.update(&data);
        let result = hasher.finalize();
        
        Ok(HashResult::new(result.to_vec()))
    })
    .await
    .map_err(|e| crate::HashError::internal(e.to_string()))?
}

async fn blake2b_hash(data: &[u8]) -> Result<HashResult> {
    let data = data.to_vec();
    
    tokio::task::spawn_blocking(move || {
        use blake2::{Blake2b512, Digest};
        
        let mut hasher = Blake2b512::new();
        hasher.update(&data);
        let result = hasher.finalize();
        
        Ok(HashResult::new(result.to_vec()))
    })
    .await
    .map_err(|e| crate::HashError::internal(e.to_string()))?
}