//! Zstd compression builder following README.md patterns

use crate::{CompressionResult, Result};

pub mod config;
pub mod compress;
pub mod stream;

pub use config::*;
pub use compress::*;
pub use stream::*;

/// Type-state marker for no level set
pub struct NoLevel;

/// Type-state marker for level set  
pub struct HasLevel(pub i32);

/// Builder for Zstd compression operations - follows README.md patterns
pub struct ZstdBuilder<L> {
    pub(crate) level: L,
    pub(crate) result_handler: Option<Box<dyn Fn(Result<CompressionResult>) -> Result<CompressionResult> + Send + Sync>>,
    pub(crate) chunk_handler: Option<Box<dyn Fn(Result<Vec<u8>>) -> Option<Vec<u8>> + Send + Sync>>,
}

impl ZstdBuilder<NoLevel> {
    /// Create a new Zstd builder with default level
    pub fn new() -> Self {
        Self {
            level: NoLevel,
            result_handler: None,
            chunk_handler: None,
        }
    }

    /// Set compression level - README.md pattern
    pub fn with_level(self, level: i32) -> ZstdBuilder<HasLevel> {
        ZstdBuilder {
            level: HasLevel(level),
            result_handler: self.result_handler,
            chunk_handler: self.chunk_handler,
        }
    }
}

impl<L> ZstdBuilder<L> {
    /// Apply on_result! handler - hidden implementation per ARCHITECTURE.md
    pub fn on_result<F>(mut self, handler: F) -> Self
    where
        F: Fn(Result<CompressionResult>) -> Result<CompressionResult> + Send + Sync + 'static,
    {
        self.result_handler = Some(Box::new(handler));
        self
    }
    
    /// Apply on_chunk! handler for streaming - hidden implementation per ARCHITECTURE.md
    pub fn on_chunk<F>(mut self, handler: F) -> Self
    where
        F: Fn(Result<Vec<u8>>) -> Option<Vec<u8>> + Send + Sync + 'static,
    {
        self.chunk_handler = Some(Box::new(handler));
        self
    }
}