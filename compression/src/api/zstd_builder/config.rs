//! Zstd compression configuration
//!
//! Contains methods for configuring compression levels and options.

use super::{ZstdBuilder, NoLevel, HasLevel};

// Methods for setting compression level
impl ZstdBuilder<NoLevel> {
    /// Set the compression level (1-22, where 1 is fastest and 22 is maximum compression)
    pub fn with_level(self, level: i32) -> ZstdBuilder<HasLevel> {
        ZstdBuilder {
            level: HasLevel(level.clamp(1, 22)),
            result_handler: self.result_handler,
            chunk_handler: self.chunk_handler,
        }
    }
    
    /// Maximum compression (level 22)
    pub fn max_compression(self) -> ZstdBuilder<HasLevel> {
        self.with_level(22)
    }
    
    /// Fast compression (level 1)
    pub fn fast_compression(self) -> ZstdBuilder<HasLevel> {
        self.with_level(1)
    }
}