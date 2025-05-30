//! Fluent compression API with zero boxing
//!
//! Usage: `let compressed = Compress::zstd().with_data(b"...").compress().await`

mod builder_traits;
mod bzip2_builder;
mod gzip_builder;
mod zip_builder;
mod zstd_builder;

pub use builder_traits::*;
pub use bzip2_builder::Bzip2Builder;
pub use gzip_builder::GzipBuilder;
pub use zip_builder::ZipBuilder;
pub use zstd_builder::ZstdBuilder;

/// Entry point for compression operations
pub struct Compress;

impl Compress {
    /// Create a Zstd compressor (best compression ratio, recommended)
    pub fn zstd() -> ZstdBuilder {
        ZstdBuilder
    }

    /// Create a Gzip compressor (widely compatible)
    pub fn gzip() -> GzipBuilder {
        GzipBuilder
    }

    /// Create a Bzip2 compressor (good compression)
    pub fn bzip2() -> Bzip2Builder {
        Bzip2Builder
    }

    /// Create a Zip compressor (legacy compatibility)
    pub fn zip() -> ZipBuilder {
        ZipBuilder
    }
}
