pub mod api;
pub mod bzip2;
mod chunk_macro;
pub mod compression_result;
pub mod error;
pub mod async_result;
pub mod gzip;
mod result_macro;
pub mod zip;
pub mod zstd;
// Re-export error types
pub use error::{CompressionError, Result};

// Re-export compression result types  
pub use compression_result::{CompressionResult, CompressionAlgorithm};
pub use async_result::{AsyncCompressionResult, AsyncCompressionResultWithHandler};

// Re-export common handlers from cryypt_common
pub use cryypt_common::{on_result, on_chunk, on_error};

// Macros are defined but unused - they were replaced with direct implementations

pub use api::*;