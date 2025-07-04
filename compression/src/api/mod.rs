//! Fluent compression API following the new pattern from README.md
//!
//! Usage: `let compressed = Compress::zstd().on_result!(|result| { ... }).compress(data).await`

mod bzip2_builder;
mod gzip_builder;
mod zip_builder;
mod zstd_builder;

pub use bzip2_builder::{Bzip2Builder, stream::Bzip2Stream};
pub use gzip_builder::{GzipBuilder, stream::GzipStream}; 
pub use zip_builder::{ZipBuilder, ZipStream};
pub use zstd_builder::{ZstdBuilder, stream::ZstdStream};

/// Entry point for compression operations
pub struct Compress;

impl Compress {
    /// Create a Zstd compressor (best compression ratio, recommended)
    pub fn zstd() -> ZstdBuilder<zstd_builder::NoLevel> {
        ZstdBuilder::new()
    }

    /// Create a Gzip compressor (widely compatible)
    pub fn gzip() -> GzipBuilder<gzip_builder::NoLevel> {
        GzipBuilder::new()
    }

    /// Create a Bzip2 compressor (good compression)
    pub fn bzip2() -> Bzip2Builder<bzip2_builder::NoLevel> {
        Bzip2Builder::new()
    }

    /// Create a Zip compressor (multi-file archives)
    pub fn zip() -> ZipBuilder<zip_builder::NoFiles> {
        ZipBuilder::new()
    }
}