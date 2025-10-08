//! Zstd compression builder following README.md patterns

use crate::{CompressionError, Result};

pub mod compress;
pub mod config;
pub mod stream;
pub mod streaming_compress;

// Re-export configuration methods for builder pattern
// pub use config::*; // Commented out - unused
// Re-export compression operations
// pub use compress::*; // Commented out - unused
// Re-export streaming types
// pub use stream::ZstdStream; // Commented out - unused

/// Type-state marker for no level set
pub struct NoLevel;

/// Type-state marker for level set  
pub struct HasLevel(pub i32);

/// Builder for Zstd compression operations - follows README.md patterns
pub struct ZstdBuilder<L> {
    pub(crate) level: L,
    pub(crate) error_handler:
        Option<Box<dyn Fn(CompressionError) -> CompressionError + Send + Sync>>,
}

/// Builder with result handler
pub struct ZstdBuilderWithHandler<L, F, T> {
    pub(crate) level: L,
    pub(crate) result_handler: F,
    pub(crate) _phantom: std::marker::PhantomData<T>,
}

/// Builder with chunk handler for streaming pattern
pub struct ZstdBuilderWithChunk<L, F> {
    pub(crate) level: L,
    pub(crate) chunk_handler: F,
    pub(crate) error_handler:
        Option<Box<dyn Fn(CompressionError) -> CompressionError + Send + Sync>>,
}

impl Default for ZstdBuilder<NoLevel> {
    fn default() -> Self {
        Self::new()
    }
}

impl ZstdBuilder<NoLevel> {
    /// Create a new Zstd builder with default level
    #[must_use]
    pub fn new() -> Self {
        Self {
            level: NoLevel,
            error_handler: None,
        }
    }

    /// Set compression level - README.md pattern
    #[must_use]
    pub fn with_level(self, level: i32) -> ZstdBuilder<HasLevel> {
        ZstdBuilder {
            level: HasLevel(level),
            error_handler: self.error_handler,
        }
    }
}

impl<L> ZstdBuilder<L> {
    /// Internal implementation for `on_result` - called by macro
    fn on_result_impl<F>(self, handler: F) -> ZstdBuilderWithHandler<L, F, Vec<u8>>
    where
        F: Fn(Result<Vec<u8>>) -> Vec<u8> + Send + 'static,
    {
        ZstdBuilderWithHandler {
            level: self.level,
            result_handler: handler,
            _phantom: std::marker::PhantomData,
        }
    }

    /// Internal implementation for `on_chunk` - called by macro
    fn on_chunk_impl<F>(self, handler: F) -> ZstdBuilderWithChunk<L, F>
    where
        F: Fn(Result<Vec<u8>>) -> Vec<u8> + Send + 'static,
    {
        ZstdBuilderWithChunk {
            level: self.level,
            chunk_handler: handler,
            error_handler: self.error_handler,
        }
    }

    /// Add `on_result` handler - transforms pattern matching internally
    #[must_use]
    pub fn on_result<F>(self, handler: F) -> ZstdBuilderWithHandler<L, F, Vec<u8>>
    where
        F: Fn(Result<Vec<u8>>) -> Vec<u8> + Send + 'static,
    {
        self.on_result_impl(handler)
    }

    /// Add `on_chunk` handler - transforms pattern matching internally
    #[must_use]
    pub fn on_chunk<F>(self, handler: F) -> ZstdBuilderWithChunk<L, F>
    where
        F: Fn(Result<Vec<u8>>) -> Vec<u8> + Send + 'static,
    {
        self.on_chunk_impl(handler)
    }

    /// Apply `on_error` handler - README.md pattern
    #[must_use]
    pub fn on_error<F>(mut self, handler: F) -> Self
    where
        F: Fn(CompressionError) -> CompressionError + Send + Sync + 'static,
    {
        self.error_handler = Some(Box::new(handler));
        self
    }
}
