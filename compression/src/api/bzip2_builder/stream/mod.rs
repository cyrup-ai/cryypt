//! Bzip2 streaming compression and decompression
//!
//! This module provides decomposed streaming operations for Bzip2 compression,
//! organized by functional responsibility.

pub mod builders;
pub mod compressor;
pub mod decompressor;
pub mod factory;
pub mod stream_core;
pub mod stream_impl;

// Re-export main types for easy access
pub use stream_core::Bzip2Stream;
