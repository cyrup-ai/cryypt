//! Fluent compression API following the new pattern from README.md
//!
//! Usage: `let compressed = Compress::zstd().on_result(|result| match result { Ok(bytes) => bytes, Err(e) => { /* handle */ Vec::new() } }).compress(data).await`

pub mod bzip2_builder;
pub mod gzip_builder;
pub mod zip_builder;
pub mod zstd_builder;

pub use bzip2_builder::{Bzip2Builder, stream::Bzip2Stream};
pub use gzip_builder::{GzipBuilder, stream::GzipStream};
pub use zip_builder::{ZipBuilder, ZipStream};
pub use zstd_builder::{ZstdBuilder, stream::ZstdStream};

/// Entry point for compression operations
pub struct Compress;

impl Compress {
    /// Create a Zstd compressor (best compression ratio, recommended)
    #[must_use]
    pub fn zstd() -> ZstdBuilder<zstd_builder::NoLevel> {
        ZstdBuilder::new()
    }

    /// Create a Gzip compressor (widely compatible)
    #[must_use]
    pub fn gzip() -> GzipBuilder<gzip_builder::NoLevel> {
        GzipBuilder::new()
    }

    /// Create a Bzip2 compressor (good compression)
    #[must_use]
    pub fn bzip2() -> Bzip2Builder<bzip2_builder::NoLevel> {
        Bzip2Builder::new()
    }

    /// Create a Zip compressor (multi-file archives)
    #[must_use]
    pub fn zip() -> ZipBuilder<zip_builder::NoFiles> {
        ZipBuilder::new()
    }
}
