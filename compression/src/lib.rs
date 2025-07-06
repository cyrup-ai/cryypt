pub mod api;
pub mod bzip2;
mod chunk_macro;
pub mod compression_result;
pub mod error;
pub mod gzip;
mod result_macro;
pub mod zip;
pub mod zstd;
// Re-export error types
pub use error::{CompressionError, Result};

// Re-export compression result type  
pub use compression_result::{CompressionResult, CompressionAlgorithm};

// Re-export common handlers from cryypt_common
pub use cryypt_common::{on_result, on_chunk, on_error};

// Export macros for internal use
pub(crate) use chunk_macro::compression_on_chunk_impl;
pub(crate) use result_macro::compression_on_result_impl;

pub use api::*;