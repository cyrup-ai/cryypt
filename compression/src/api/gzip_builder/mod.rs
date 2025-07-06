//! Gzip compression builder - core types and entry point
//!
//! Contains the main builder types, type-state markers, and entry points for Gzip compression.

use crate::{CompressionResult, CompressionError, Result};

pub mod config;
pub mod compress;
pub mod stream;

// Re-export configuration methods for builder pattern  
// pub use config::*;
// Re-export compression operations
// pub use compress::*;
// Re-export streaming types
// pub use stream::GzipStream;

/// Type-state marker for no level set
pub struct NoLevel;

/// Type-state marker for level set  
pub struct HasLevel(pub u32);

/// Builder for Gzip compression operations
pub struct GzipBuilder<L> {
    pub(crate) level: L,
    pub(crate) chunk_handler: Option<Box<dyn Fn(Result<Vec<u8>>) -> Option<Vec<u8>> + Send + Sync>>,
    pub(crate) error_handler: Option<Box<dyn Fn(CompressionError) -> CompressionError + Send + Sync>>,
}

/// Builder with result handler for unwrapping pattern
pub struct GzipBuilderWithHandler<L, F, T> {
    pub(crate) level: L,
    pub(crate) result_handler: F,
    pub(crate) _phantom: std::marker::PhantomData<T>,
}

/// Builder with chunk handler for streaming pattern
pub struct GzipBuilderWithChunk<L, C> {
    pub(crate) level: L,
    pub(crate) chunk_handler: C,
    pub(crate) error_handler: Option<Box<dyn Fn(CompressionError) -> CompressionError + Send + Sync>>,
}

impl GzipBuilder<NoLevel> {
    /// Create a new Gzip builder with default level
    pub fn new() -> Self {
        Self {
            level: NoLevel,
            chunk_handler: None,
            error_handler: None,
        }
    }
    
    // with_level method is defined in config.rs
}

// Methods for adding result and chunk handlers
impl<L> GzipBuilder<L> {
    /// Apply on_result handler - transforms Result<T> -> T for unwrapping pattern
    pub fn on_result<F, T>(self, handler: F) -> GzipBuilderWithHandler<L, F, T>
    where
        F: FnOnce(Result<CompressionResult>) -> T + Send + 'static,
        T: cryypt_common::NotResult + Send + 'static,
    {
        GzipBuilderWithHandler {
            level: self.level,
            result_handler: handler,
            _phantom: std::marker::PhantomData,
        }
    }
    
    /// Apply on_chunk handler for streaming operations
    pub fn on_chunk<C>(self, handler: C) -> GzipBuilderWithChunk<L, C>
    where
        C: Fn(Result<Vec<u8>>) -> Option<Vec<u8>> + Send + Sync + 'static,
    {
        GzipBuilderWithChunk {
            level: self.level,
            chunk_handler: handler,
            error_handler: self.error_handler,
        }
    }
    
    /// Apply on_error handler for error transformation
    pub fn on_error<F>(mut self, handler: F) -> Self
    where
        F: Fn(CompressionError) -> CompressionError + Send + Sync + 'static,
    {
        self.error_handler = Some(Box::new(handler));
        self
    }
}