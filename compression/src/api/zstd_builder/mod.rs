//! Zstd compression builder following README.md patterns

use crate::{CompressionResult, CompressionError, Result};

pub mod config;
pub mod compress;
pub mod stream;

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
    pub(crate) error_handler: Option<Box<dyn Fn(CompressionError) -> CompressionError + Send + Sync>>,
}

/// Builder with result handler
pub struct ZstdBuilderWithHandler<L, F, T> {
    pub(crate) level: L,
    pub(crate) result_handler: F,
    pub(crate) _phantom: std::marker::PhantomData<T>,
}

/// Builder with chunk handler for streaming pattern
pub struct ZstdBuilderWithChunk<L, C> {
    pub(crate) level: L,
    pub(crate) chunk_handler: C,
    pub(crate) error_handler: Option<Box<dyn Fn(CompressionError) -> CompressionError + Send + Sync>>,
}

impl ZstdBuilder<NoLevel> {
    /// Create a new Zstd builder with default level
    pub fn new() -> Self {
        Self {
            level: NoLevel,
            error_handler: None,
        }
    }

    /// Set compression level - README.md pattern
    pub fn with_level(self, level: i32) -> ZstdBuilder<HasLevel> {
        ZstdBuilder {
            level: HasLevel(level),
            error_handler: self.error_handler,
        }
    }
}

impl<L> ZstdBuilder<L> {
    /// Apply on_result handler - README.md pattern
    pub fn on_result<F, T>(self, handler: F) -> ZstdBuilderWithHandler<L, F, T>
    where
        F: FnOnce(Result<CompressionResult>) -> T + Send + 'static,
        T: cryypt_common::NotResult + Send + 'static,
    {
        ZstdBuilderWithHandler {
            level: self.level,
            result_handler: handler,
            _phantom: std::marker::PhantomData,
        }
    }
    
    /// Apply on_chunk handler for streaming - README.md pattern
    pub fn on_chunk<C>(self, handler: C) -> ZstdBuilderWithChunk<L, C>
    where
        C: Fn(Result<Vec<u8>>) -> Option<Vec<u8>> + Send + Sync + 'static,
    {
        ZstdBuilderWithChunk {
            level: self.level,
            chunk_handler: handler,
            error_handler: self.error_handler,
        }
    }
    
    /// Apply on_error handler - README.md pattern
    pub fn on_error<F>(mut self, handler: F) -> Self
    where
        F: Fn(CompressionError) -> CompressionError + Send + Sync + 'static,
    {
        self.error_handler = Some(Box::new(handler));
        self
    }
}