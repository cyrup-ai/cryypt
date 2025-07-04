//! Bzip2 compression builder - core types and entry point
//!
//! Contains the main builder types, type-state markers, and entry points for Bzip2 compression.

use crate::{CompressionResult, CompressionAlgorithm, Result};

pub mod config;
pub mod compress;
pub mod stream;

pub use config::*;
pub use compress::*;
pub use stream::*;

/// Type-state marker for no level set
pub struct NoLevel;

/// Type-state marker for level set  
pub struct HasLevel(pub u32);

/// Builder for Bzip2 compression operations
pub struct Bzip2Builder<L> {
    pub(crate) level: L,
    pub(crate) result_handler: Option<Box<dyn Fn(Result<CompressionResult>) -> Result<CompressionResult> + Send + Sync>>,
    pub(crate) chunk_handler: Option<Box<dyn Fn(Result<Vec<u8>>) -> Option<Vec<u8>> + Send + Sync>>,
}

impl Bzip2Builder<NoLevel> {
    /// Create a new Bzip2 builder with default level
    pub fn new() -> Self {
        Self {
            level: NoLevel,
            result_handler: None,
            chunk_handler: None,
        }
    }
}

// Methods for adding result and chunk handlers
impl<L> Bzip2Builder<L> {
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