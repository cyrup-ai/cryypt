//! Gzip compression builder - core types and entry point
//!
//! Contains the main builder types, type-state markers, and entry points for Gzip compression.

use crate::{CompressionError, Result};

/// Type alias for chunk handler functions
type ChunkHandler = Box<dyn Fn(Result<Vec<u8>>) -> Option<Vec<u8>> + Send + Sync>;

pub mod compress;
pub mod config;
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
    pub(crate) chunk_handler: Option<ChunkHandler>,
    pub(crate) error_handler:
        Option<Box<dyn Fn(CompressionError) -> CompressionError + Send + Sync>>,
}

/// Builder with result handler for unwrapping pattern
pub struct GzipBuilderWithHandler<L, F, T> {
    pub(crate) level: L,
    pub(crate) result_handler: F,
    pub(crate) _phantom: std::marker::PhantomData<T>,
}

/// Builder with chunk handler for streaming pattern
pub struct GzipBuilderWithChunk<L, F> {
    pub(crate) level: L,
    pub(crate) chunk_handler: F,
    pub(crate) error_handler:
        Option<Box<dyn Fn(CompressionError) -> CompressionError + Send + Sync>>,
}

impl Default for GzipBuilder<NoLevel> {
    fn default() -> Self {
        Self::new()
    }
}

impl GzipBuilder<NoLevel> {
    /// Create a new Gzip builder with default level
    #[must_use]
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
    /// Internal implementation for `on_result` - called by macro
    fn on_result_impl<F>(self, handler: F) -> GzipBuilderWithHandler<L, F, Vec<u8>>
    where
        F: Fn(Result<Vec<u8>>) -> Vec<u8> + Send + 'static,
    {
        GzipBuilderWithHandler {
            level: self.level,
            result_handler: handler,
            _phantom: std::marker::PhantomData,
        }
    }

    /// Internal implementation for `on_chunk` - called by macro
    fn on_chunk_impl<F>(self, handler: F) -> GzipBuilderWithChunk<L, F>
    where
        F: Fn(Result<Vec<u8>>) -> Vec<u8> + Send + 'static,
    {
        GzipBuilderWithChunk {
            level: self.level,
            chunk_handler: handler,
            error_handler: self.error_handler,
        }
    }

    /// Add `on_result` handler - transforms pattern matching internally
    #[must_use]
    pub fn on_result<F>(self, handler: F) -> GzipBuilderWithHandler<L, F, Vec<u8>>
    where
        F: Fn(Result<Vec<u8>>) -> Vec<u8> + Send + 'static,
    {
        self.on_result_impl(handler)
    }

    /// Add `on_chunk` handler - transforms pattern matching internally
    #[must_use]
    pub fn on_chunk<F>(self, handler: F) -> GzipBuilderWithChunk<L, F>
    where
        F: Fn(Result<Vec<u8>>) -> Vec<u8> + Send + 'static,
    {
        self.on_chunk_impl(handler)
    }

    /// Apply `on_error` handler for error transformation
    #[must_use]
    pub fn on_error<F>(mut self, handler: F) -> Self
    where
        F: Fn(CompressionError) -> CompressionError + Send + Sync + 'static,
    {
        self.error_handler = Some(Box::new(handler));
        self
    }
}
