//! Common types and base methods for hash builders

use super::super::{
    passes::HashPasses,
    HasPasses, HasSalt, NoPasses, NoSalt,
};
use crate::{HashResult, Result, HashError};

/// Builder for hash operations
pub struct HashBuilder<H, D, S, P> {
    pub(crate) hasher: H,
    pub(crate) data: D,
    pub(crate) salt: S,
    pub(crate) passes: P,
    pub(crate) result_handler: Option<Box<dyn Fn(Result<HashResult>) -> Vec<u8> + Send + Sync>>,
    pub(crate) chunk_handler: Option<Box<dyn Fn(Result<Vec<u8>>) -> Option<Vec<u8>> + Send + Sync>>,
    pub(crate) error_handler: Option<Box<dyn Fn(HashError) -> HashError + Send + Sync>>,
}

// Methods for adding result handler
impl<H, D, S, P> HashBuilder<H, D, S, P> {
    /// Apply on_result! handler
    #[must_use]
    pub fn on_result<F>(mut self, handler: F) -> Self
    where
        F: Fn(Result<HashResult>) -> Vec<u8> + Send + Sync + 'static,
    {
        self.result_handler = Some(Box::new(handler));
        self
    }
    
    /// Apply on_chunk! handler for streaming
    #[must_use]
    pub fn on_chunk<F>(mut self, handler: F) -> Self
    where
        F: Fn(Result<Vec<u8>>) -> Option<Vec<u8>> + Send + Sync + 'static,
    {
        self.chunk_handler = Some(Box::new(handler));
        self
    }
    
    /// Apply on_error handler - transforms errors but passes through success
    #[must_use]
    pub fn on_error<E>(mut self, handler: E) -> Self
    where
        E: Fn(HashError) -> HashError + Send + Sync + 'static,
    {
        self.error_handler = Some(Box::new(handler));
        self
    }
}

// Methods for adding key (for HMAC)
impl<H, D, P> HashBuilder<H, D, NoSalt, P> {
    /// Set the key for HMAC operations
    #[must_use]
    pub fn with_key<T: Into<Vec<u8>>>(self, key: T) -> HashBuilder<H, D, HasSalt, P> {
        HashBuilder {
            hasher: self.hasher,
            data: self.data,
            salt: HasSalt(key.into()),
            passes: self.passes,
            result_handler: self.result_handler,
            chunk_handler: self.chunk_handler,
            error_handler: self.error_handler,
        }
    }
}

// Methods for setting passes (for iterative hashing)
impl<H, D, S> HashBuilder<H, D, S, NoPasses> {
    /// Set the number of passes for iterative hashing
    #[must_use]
    pub fn with_passes(self, passes: HashPasses) -> HashBuilder<H, D, S, HasPasses> {
        HashBuilder {
            hasher: self.hasher,
            data: self.data,
            salt: self.salt,
            passes: HasPasses(passes),
            result_handler: self.result_handler,
            chunk_handler: self.chunk_handler,
            error_handler: self.error_handler,
        }
    }
}