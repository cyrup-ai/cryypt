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

// Re-export the on_result! macro
pub use compression_on_result as on_result;

pub use api::*;
