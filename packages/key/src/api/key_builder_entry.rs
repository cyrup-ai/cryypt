//! Entry point that connects Cryypt::key() to existing builders

use super::{KeyGenerator, KeyRetriever};

/// Entry point for key operations from Cryypt::key()
#[derive(Debug, Clone, Copy)]
pub struct KeyBuilder;

impl KeyBuilder {
    /// Create a new KeyBuilder
    #[inline(always)]
    pub const fn new() -> Self {
        Self
    }

    /// Start key generation flow
    /// Delegates to existing KeyGenerator
    #[inline(always)]
    pub const fn generate(self) -> KeyGenerator {
        KeyGenerator::new()
    }

    /// Start key retrieval flow  
    /// Delegates to existing KeyRetriever
    #[inline(always)]
    pub const fn retrieve(self) -> KeyRetriever {
        KeyRetriever::new()
    }
}