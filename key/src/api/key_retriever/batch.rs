//! Batch key retrieval operations
//!
//! Contains batch processing functionality for high-throughput key retrieval scenarios.

use super::{KeyRetrieverReady, SecureRetrievedKey, StreamConfig};
use crate::{
    traits::{KeyRetrieval, KeyStorage},
    KeyError,
};
use crossbeam_channel::{bounded, unbounded, Receiver};
use zeroize::Zeroize;

/// Batch key retrieval for high-throughput scenarios with security isolation
pub struct KeyRetrieverBatch<S: KeyStorage + KeyRetrieval + Send + Sync + Clone + 'static> {
    pub(crate) retriever: KeyRetrieverReady<S>,
    pub(crate) suffixes: Vec<String>,
    pub(crate) stream_config: StreamConfig,
}

impl<S: KeyStorage + KeyRetrieval + Send + Sync + Clone + 'static> KeyRetrieverReady<S> {
    /// Create batch retriever for multiple keys with same namespace/version
    #[inline]
    pub fn batch_with_suffixes(
        self,
        suffixes: Vec<String>,
    ) -> Result<KeyRetrieverBatch<S>, KeyError> {
        if suffixes.is_empty() {
            return Err(KeyError::invalid_key("Batch suffixes cannot be empty"));
        }
        if suffixes.len() > 1000 {
            return Err(KeyError::invalid_key(
                "Batch count too large (max 1000 for security)",
            ));
        }

        let stream_config = StreamConfig::bounded(suffixes.len());
        Ok(KeyRetrieverBatch {
            retriever: self,
            suffixes,
            stream_config,
        })
    }
}

impl<S: KeyStorage + KeyRetrieval + Send + Sync + Clone + 'static> KeyRetrieverBatch<S> {
    /// Configure the stream for batch retrieval
    #[inline]
    pub fn with_stream_config(mut self, config: StreamConfig) -> Self {
        self.stream_config = config;
        self
    }

    /// Retrieve all keys and stream results securely
    pub async fn retrieve_all(self) -> Receiver<Result<SecureRetrievedKey, KeyError>> {
        let (tx, rx) = if self.stream_config.bounded {
            bounded(self.stream_config.capacity)
        } else {
            unbounded()
        };

        let suffixes = self.suffixes;
        let retriever = self.retriever;

        tokio::spawn(async move {
            for suffix in suffixes {
                // Clone retriever for each key to ensure isolation
                let r = KeyRetrieverReady {
                    store: retriever.store.clone(),
                    namespace: retriever.namespace.clone(),
                    version: retriever.version,
                };

                let key_id = r.generate_key_id(Some(&suffix));
                let result = r.retrieve_internal(&key_id).await;

                if tx.send(result).is_err() {
                    // Receiver dropped, stop retrieving
                    break;
                }
            }
        });

        rx
    }

    /// Retrieve all keys and collect into Vec securely
    pub async fn retrieve_collect(self) -> Result<Vec<SecureRetrievedKey>, KeyError> {
        let count = self.suffixes.len();
        let mut keys = Vec::with_capacity(count);
        let rx = self.retrieve_all().await;

        // Collect all results securely
        for _ in 0..count {
            match rx.recv() {
                Ok(Ok(key)) => keys.push(key),
                Ok(Err(e)) => {
                    // Clear any partial results on error for security
                    for key in &mut keys {
                        key.data.zeroize();
                    }
                    return Err(e);
                }
                Err(_) => {
                    // Clear any partial results on channel error
                    for key in &mut keys {
                        key.data.zeroize();
                    }
                    return Err(KeyError::internal(
                        "Channel disconnected during batch retrieval",
                    ));
                }
            }
        }

        Ok(keys)
    }
}