//! Gzip streaming compression and decompression modules
//!
//! Contains streaming operations and related types for Gzip compression.

pub mod builders;
pub mod compressor;
pub mod decompressor;
pub mod stream_core;
pub mod stream_impl;

// Re-export main types and functions
pub use compressor::{
    GzipCompressor, GzipDecompressor, create_gzip_compressor, create_gzip_decompressor,
};
pub use stream_core::GzipStream;

// Import parent types for builder implementations
use super::{GzipBuilderWithChunk, HasLevel, NoLevel};
