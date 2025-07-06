//! Gzip compression builder - core types and entry point
//!
//! Contains the main builder types, type-state markers, and entry points for Gzip compression.

use crate::{CompressionResult, Result};

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
    pub(crate) result_handler: Option<Box<dyn Fn(Result<CompressionResult>) -> Result<CompressionResult> + Send + Sync>>,
    pub(crate) chunk_handler: Option<Box<dyn Fn(Result<Vec<u8>>) -> Option<Vec<u8>> + Send + Sync>>,
}

impl GzipBuilder<NoLevel> {
    /// Create a new Gzip builder with default level
    pub fn new() -> Self {
        Self {
            level: NoLevel,
            result_handler: None,
            chunk_handler: None,
        }
    }
}

// Methods for adding result and chunk handlers
impl<L> GzipBuilder<L> {
    /// Apply on_result! handler
    pub fn on_result<F>(mut self, handler: F) -> Self
    where
        F: Fn(Result<CompressionResult>) -> Result<CompressionResult> + Send + Sync + 'static,
    {
        self.result_handler = Some(Box::new(handler));
        self
    }
    
    /// Apply on_chunk! handler for streaming
    pub fn on_chunk<F>(mut self, handler: F) -> Self
    where
        F: Fn(Result<Vec<u8>>) -> Option<Vec<u8>> + Send + Sync + 'static,
    {
        self.chunk_handler = Some(Box::new(handler));
        self
    }
}