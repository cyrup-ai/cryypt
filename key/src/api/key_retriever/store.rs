//! Store integration and single key retrieval operations
//!
//! Contains core retrieval functionality with security validation and error handling.

use super::{KeyRetrieverReady, SecureRetrievedKey, StreamConfig};
use crate::{
    traits::{KeyRetrieval, KeyStorage},
    KeyError, KeyId,
};
use crossbeam_channel::{bounded, unbounded, Receiver};

impl<S: KeyStorage + KeyRetrieval + Send + Sync + Clone + 'static> KeyRetrieverReady<S> {
    /// Internal retrieval with security wrapper
    pub(crate) async fn retrieve_internal(&self, key_id: &crate::SimpleKeyId) -> Result<SecureRetrievedKey, KeyError> {
        // Validate version
        if self.version == 0 {
            return Err(KeyError::invalid_key("Key version must be non-zero"));
        }
        if self.version > 1_000_000 {
            return Err(KeyError::invalid_key(
                "Key version too large (max 1,000,000)",
            ));
        }

        // Validate namespace
        if self.namespace.is_empty() {
            return Err(KeyError::invalid_key("Namespace cannot be empty"));
        }
        if self.namespace.len() > 64 {
            return Err(KeyError::invalid_key(
                "Namespace too long (max 64 characters)",
            ));
        }
        if !self.namespace
            .chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
        {
            return Err(KeyError::invalid_key(
                "Namespace contains invalid characters",
            ));
        }

        match self.store.retrieve(key_id).await {
            Ok(key_bytes) => {
                // Wrap in secure buffer for automatic cleanup
                Ok(SecureRetrievedKey::new(key_id.clone(), key_bytes))
            }
            Err(_) => Err(KeyError::KeyNotFound {
                id: key_id.id().to_string(),
                version: Some(self.version),
            }),
        }
    }

    /// Retrieve an existing key using the configured parameters (raw access)
    #[inline]
    pub async fn retrieve_raw<F, T>(self, handler: F) -> T
    where
        F: FnOnce(Result<SecureRetrievedKey, KeyError>) -> T,
    {
        let key_id = self.generate_key_id(None);
        let result = self.retrieve_internal(&key_id).await;
        handler(result)
    }

    /// Retrieve an existing key and return ActualKey for use with on_result! macro
    /// This enables the README.md pattern with .await?
    #[inline]
    pub async fn retrieve_key(self) -> Result<crate::api::ActualKey, KeyError> {
        let key_id = self.generate_key_id(None);
        let retrieved_key = self.retrieve_internal(&key_id).await?;
        let key_bytes = retrieved_key.into_key_bytes();
        Ok(crate::api::ActualKey::from_bytes(key_bytes))
    }

    /// Retrieve key with handler for README.md alternative syntax
    /// This enables: KeyRetriever::new()...retrieve(|result| match result { Ok(result) => Ok(result), Err(e) => Err(e) }).await?
    /// Note: The README shows pseudo-syntax, but in actual Rust this needs to be a proper match expression
    #[inline]
    pub async fn retrieve<F>(self, handler: F) -> Result<crate::api::ActualKey, KeyError>
    where
        F: FnOnce(Result<crate::api::ActualKey, KeyError>) -> Result<crate::api::ActualKey, KeyError>,
    {
        let result = self.retrieve_key().await;
        handler(result)
    }

    /// Retrieve a key with a specific suffix
    #[inline]
    pub async fn retrieve_with_suffix<F, T>(self, suffix: &str, handler: F) -> T
    where
        F: FnOnce(Result<SecureRetrievedKey, KeyError>) -> T,
    {
        let key_id = self.generate_key_id(Some(suffix));
        let result = self.retrieve_internal(&key_id).await;
        handler(result)
    }

    /// Stream single key retrieval with default configuration
    #[inline]
    pub async fn retrieve_stream(self) -> Receiver<Result<SecureRetrievedKey, KeyError>> {
        self.retrieve_stream_with_config(StreamConfig::default_bounded())
            .await
    }

    /// Stream single key retrieval with unbounded channel
    #[inline]
    pub async fn retrieve_stream_unbounded(self) -> Receiver<Result<SecureRetrievedKey, KeyError>> {
        self.retrieve_stream_with_config(StreamConfig::unbounded())
            .await
    }

    /// Stream with custom configuration
    #[inline]
    pub async fn retrieve_stream_with_config(
        self,
        config: StreamConfig,
    ) -> Receiver<Result<SecureRetrievedKey, KeyError>> {
        let (tx, rx) = if config.bounded {
            bounded(config.capacity)
        } else {
            unbounded()
        };

        let retriever = self;
        tokio::spawn(async move {
            let key_id = retriever.generate_key_id(None);
            let result = retriever.retrieve_internal(&key_id).await;
            let _ = tx.send(result);
        });

        rx
    }
}

impl<S: KeyStorage + KeyRetrieval + Send + Sync + Clone + 'static> crate::result_macro::KeyProducer for KeyRetrieverReady<S> {
    async fn produce_key(self) -> Result<crate::api::ActualKey, crate::KeyError> {
        self.retrieve_key().await
    }
}