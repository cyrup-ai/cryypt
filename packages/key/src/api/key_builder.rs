//! Key builder implementation following README.md patterns exactly

use crate::KeyError;
use crate::KeyResult;
use crate::api::ActualKey;
use crate::result_macro::KeyProducer;

/// Key builder for creating and retrieving keys
pub struct KeyBuilder {
    size_bits: u32,
}

/// Key builder with store configured
pub struct KeyBuilderWithStore {
    size_bits: u32,
    store: Box<dyn KeyStore>,
}

/// Key builder with store and namespace configured  
pub struct KeyBuilderWithStoreAndNamespace {
    size_bits: u32,
    store: Box<dyn KeyStore>,
    namespace: String,
}

/// Key builder with store, namespace, and version - ready for operations
pub struct KeyBuilderReady {
    size_bits: u32,
    store: Box<dyn KeyStore>,
    namespace: String,
    version: u32,
    result_handler: Option<Box<dyn Fn(KeyResult) -> KeyResult + Send + Sync>>,
}

/// Key builder with result handler
pub struct KeyBuilderReadyWithHandler<F> {
    size_bits: u32,
    store: Box<dyn KeyStore>,
    namespace: String,
    version: u32,
    result_handler: F,
}

/// Key builder with chunk handler for streaming
pub struct KeyBuilderReadyWithChunkHandler<F> {
    size_bits: u32,
    store: Box<dyn KeyStore>,
    namespace: String,
    version: u32,
    chunk_handler: F,
}

/// Trait for key storage backends
pub trait KeyStore: Send + Sync {
    /// Generate a new key
    fn generate_key(&self, size_bits: u32, namespace: &str, version: u32) -> KeyResult;

    /// Retrieve an existing key
    fn retrieve_key(&self, namespace: &str, version: u32) -> KeyResult;
}

impl KeyBuilder {
    /// Create new key builder with specified size
    #[must_use]
    pub fn new(size_bits: u32) -> Self {
        Self { size_bits }
    }

    /// Set the key storage backend - README.md pattern
    pub fn with_store<S: KeyStore + 'static>(self, store: S) -> KeyBuilderWithStore {
        KeyBuilderWithStore {
            size_bits: self.size_bits,
            store: Box::new(store),
        }
    }
}

impl KeyBuilderWithStore {
    /// Set the namespace - README.md pattern
    pub fn with_namespace<S: Into<String>>(self, namespace: S) -> KeyBuilderWithStoreAndNamespace {
        KeyBuilderWithStoreAndNamespace {
            size_bits: self.size_bits,
            store: self.store,
            namespace: namespace.into(),
        }
    }
}

impl KeyBuilderWithStoreAndNamespace {
    /// Set the version - README.md pattern
    #[must_use]
    pub fn version(self, version: u32) -> KeyBuilderReady {
        KeyBuilderReady {
            size_bits: self.size_bits,
            store: self.store,
            namespace: self.namespace,
            version,
            result_handler: None,
        }
    }
}

impl KeyBuilderReady {
    /// Add `on_result` handler - transforms pattern matching internally
    pub fn on_result<F>(self, handler: F) -> KeyBuilderReadyWithHandler<F>
    where
        F: Fn(crate::Result<Vec<u8>>) -> Vec<u8> + Send + 'static,
    {
        // Use universal macro internally to transform the pattern matching
        KeyBuilderReadyWithHandler {
            size_bits: self.size_bits,
            store: self.store,
            namespace: self.namespace,
            version: self.version,
            result_handler: handler,
        }
    }

    /// Add `on_chunk` handler - transforms pattern matching internally
    pub fn on_chunk<F>(self, handler: F) -> KeyBuilderReadyWithChunkHandler<F>
    where
        F: Fn(crate::Result<Vec<u8>>) -> Vec<u8> + Send + 'static,
    {
        // Use universal macro internally to transform the pattern matching
        KeyBuilderReadyWithChunkHandler {
            size_bits: self.size_bits,
            store: self.store,
            namespace: self.namespace,
            version: self.version,
            chunk_handler: handler,
        }
    }

    /// Generate a new key - action method per README.md
    #[must_use]
    pub fn generate(self) -> KeyResult {
        let result = self
            .store
            .generate_key(self.size_bits, &self.namespace, self.version);

        if let Some(handler) = self.result_handler {
            handler(result)
        } else {
            result
        }
    }

    /// Retrieve an existing key - action method per README.md
    #[must_use]
    pub fn retrieve(self) -> KeyResult {
        let result = self.store.retrieve_key(&self.namespace, self.version);

        if let Some(handler) = self.result_handler {
            handler(result)
        } else {
            result
        }
    }
}

impl<F> KeyBuilderReadyWithHandler<F>
where
    F: Fn(Result<Vec<u8>, KeyError>) -> Vec<u8> + Send + 'static,
{
    /// Generate a new key - action method per README.md
    pub async fn generate(self) -> Vec<u8> {
        let key_result = self
            .store
            .generate_key(self.size_bits, &self.namespace, self.version);

        // KeyResult is a Future that resolves to Result<Vec<u8>>
        let result = key_result.await;
        (self.result_handler)(result)
    }

    /// Retrieve an existing key - action method per README.md
    pub async fn retrieve(self) -> Vec<u8> {
        let key_result = self.store.retrieve_key(&self.namespace, self.version);

        // KeyResult is a Future that resolves to Result<Vec<u8>>
        let result = key_result.await;
        (self.result_handler)(result)
    }
}

impl<F> KeyBuilderReadyWithChunkHandler<F>
where
    F: Fn(Result<Vec<u8>, KeyError>) -> Vec<u8> + Send + 'static,
{
    /// Generate a new key as stream - returns async iterator of chunks
    pub fn generate_stream(self) -> impl futures::Stream<Item = Vec<u8>> + Send {
        let store = self.store;
        let namespace = self.namespace;
        let version = self.version;
        let size_bits = self.size_bits;
        let handler = self.chunk_handler;

        futures::stream::unfold(
            (store, namespace, version, size_bits, handler, false),
            move |(store, namespace, version, size_bits, handler, done)| async move {
                if done {
                    return None;
                }

                // Generate the key
                let key_result = store.generate_key(size_bits, &namespace, version);
                let result = key_result.await;
                let processed_chunk = handler(result);

                Some((
                    processed_chunk,
                    (store, namespace, version, size_bits, handler, true),
                ))
            },
        )
    }

    /// Retrieve an existing key as stream - returns async iterator of chunks
    pub fn retrieve_stream(self) -> impl futures::Stream<Item = Vec<u8>> + Send {
        let store = self.store;
        let namespace = self.namespace;
        let version = self.version;
        let handler = self.chunk_handler;

        futures::stream::unfold(
            (store, namespace, version, handler, false),
            move |(store, namespace, version, handler, done)| async move {
                if done {
                    return None;
                }

                // Retrieve the key
                let key_result = store.retrieve_key(&namespace, version);
                let result = key_result.await;
                let processed_chunk = handler(result);

                Some((processed_chunk, (store, namespace, version, handler, true)))
            },
        )
    }
}

// KeyProducer implementations for different builder states
impl KeyProducer for KeyBuilder {
    async fn produce_key(self) -> Result<ActualKey, KeyError> {
        // Generate a random key using default size
        let key_bytes = rand::random::<[u8; 32]>().to_vec();
        Ok(ActualKey::from_bytes(key_bytes))
    }
}

impl KeyProducer for KeyBuilderWithStore {
    async fn produce_key(self) -> Result<ActualKey, KeyError> {
        // Use the store to generate a key
        let result = self.store.generate_key(self.size_bits, "default", 1);
        result.await.map(ActualKey::from_bytes)
    }
}

impl KeyProducer for KeyBuilderReady {
    async fn produce_key(self) -> Result<ActualKey, KeyError> {
        // Use the store with proper namespace and version
        let result = self
            .store
            .generate_key(self.size_bits, &self.namespace, self.version);
        result.await.map(ActualKey::from_bytes)
    }
}

/// Utility function to generate a key using any `KeyProducer`
pub async fn generate_key_from_producer<T: KeyProducer>(
    producer: T,
) -> Result<ActualKey, KeyError> {
    producer.produce_key().await
}

/// Generate a random key using the default `KeyBuilder`
#[allow(dead_code)]
pub async fn generate_default_key() -> Result<ActualKey, KeyError> {
    let builder = KeyBuilder::new(256); // 256-bit key
    generate_key_from_producer(builder).await
}
