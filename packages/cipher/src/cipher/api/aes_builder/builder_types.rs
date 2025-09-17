//! AES builder type definitions

/// Initial AES builder - entry point
pub struct AesBuilder;

/// AES builder with key
pub struct AesWithKey {
    pub(super) key: Vec<u8>,
    pub(super) aad: Option<Vec<u8>>,
}

/// AES builder with key and result handler
pub struct AesWithKeyAndHandler<F, T> {
    pub(super) key: Vec<u8>,
    pub(super) aad: Option<Vec<u8>>,
    pub(super) result_handler: F,
    pub(super) _phantom: std::marker::PhantomData<T>,
}

/// AES builder with key and chunk handler for streaming
pub struct AesWithKeyAndChunkHandler<F> {
    pub(super) key: Vec<u8>,
    pub(super) aad: Option<Vec<u8>>,
    pub(super) chunk_handler: F,
}

impl Default for AesBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl AesBuilder {
    /// Create new AES builder
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Add key to builder - README.md pattern
    #[must_use]
    pub fn with_key<T: Into<Vec<u8>>>(self, key: T) -> AesWithKey {
        AesWithKey::new(key.into())
    }
}

impl AesWithKey {
    /// Create AES builder with key
    #[must_use]
    pub fn new(key: Vec<u8>) -> Self {
        Self { key, aad: None }
    }

    /// Add additional authenticated data (AAD) for AES-GCM
    #[must_use]
    pub fn with_aad<T: Into<Vec<u8>>>(mut self, aad: T) -> Self {
        self.aad = Some(aad.into());
        self
    }

    /// Internal implementation for `on_result` - called by macro
    pub(super) fn on_result_impl<F>(self, handler: F) -> AesWithKeyAndHandler<F, Vec<u8>>
    where
        F: Fn(crate::Result<Vec<u8>>) -> Vec<u8> + Send + 'static,
    {
        AesWithKeyAndHandler {
            key: self.key,
            aad: self.aad,
            result_handler: handler,
            _phantom: std::marker::PhantomData,
        }
    }

    /// Add `on_result` handler - transforms pattern matching internally  
    #[must_use]
    pub fn on_result<F>(self, handler: F) -> AesWithKeyAndHandler<F, Vec<u8>>
    where
        F: Fn(crate::Result<Vec<u8>>) -> Vec<u8> + Send + 'static,
    {
        self.on_result_impl(cryypt_common::transform_on_result!(handler))
    }
}

impl AesWithKey {
    /// Add `on_chunk` handler for streaming operations
    #[must_use]
    pub fn on_chunk<F>(self, handler: F) -> AesWithKeyAndChunkHandler<F>
    where
        F: Fn(crate::Result<Vec<u8>>) -> Vec<u8> + Send + 'static,
    {
        AesWithKeyAndChunkHandler {
            key: self.key,
            aad: self.aad,
            chunk_handler: cryypt_common::transform_on_result!(handler),
        }
    }
}
