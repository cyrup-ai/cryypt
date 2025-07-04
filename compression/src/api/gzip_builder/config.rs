//! Gzip compression configuration
//!
//! Contains methods for configuring compression levels and options.

use super::{GzipBuilder, NoLevel, HasLevel};

// Methods for setting compression level
impl GzipBuilder<NoLevel> {
    /// Set the compression level (1-9, where 1 is fastest and 9 is maximum compression)
    pub fn with_level(self, level: u32) -> GzipBuilder<HasLevel> {
        GzipBuilder {
            level: HasLevel(level.clamp(1, 9)),
            result_handler: self.result_handler,
            chunk_handler: self.chunk_handler,
        }
    }
    
    /// Maximum compression (level 9)
    pub fn max_compression(self) -> GzipBuilder<HasLevel> {
        self.with_level(9)
    }
    
    /// Fast compression (level 1)
    pub fn fast_compression(self) -> GzipBuilder<HasLevel> {
        self.with_level(1)
    }
}