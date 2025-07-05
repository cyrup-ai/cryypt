//! Key builder implementation following README.md patterns exactly

use crate::KeyResult;
use crate::result_macro::KeyProducer;
use crate::api::ActualKey;
use crate::KeyError;

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

/// Trait for key storage backends
pub trait KeyStore: Send + Sync {
    /// Generate a new key
    fn generate_key(&self, size_bits: u32, namespace: &str, version: u32) -> KeyResult;
    
    /// Retrieve an existing key
    fn retrieve_key(&self, namespace: &str, version: u32) -> KeyResult;
}

impl KeyBuilder {
    /// Create new key builder with specified size
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
    /// Add on_result handler - README.md pattern
    pub fn on_result<F>(mut self, handler: F) -> Self
    where
        F: Fn(KeyResult) -> KeyResult + Send + Sync + 'static,
    {
        self.result_handler = Some(Box::new(handler));
        self
    }

    /// Generate a new key - action method per README.md
    pub async fn generate(self) -> KeyResult {
        let result = self.store.generate_key(self.size_bits, &self.namespace, self.version);
        
        if let Some(handler) = self.result_handler {
            handler(result)
        } else {
            result
        }
    }

    /// Retrieve an existing key - action method per README.md
    pub async fn retrieve(self) -> KeyResult {
        let result = self.store.retrieve_key(&self.namespace, self.version);
        
        if let Some(handler) = self.result_handler {
            handler(result)
        } else {
            result
        }
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
        let result = self.store.generate_key(self.size_bits, &self.namespace, self.version);
        result.await.map(ActualKey::from_bytes)
    }
}

/// Utility function to generate a key using any KeyProducer
pub async fn generate_key_from_producer<T: KeyProducer>(producer: T) -> Result<ActualKey, KeyError> {
    producer.produce_key().await
}