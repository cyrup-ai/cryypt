//! Batch key retrieval operations
//!
//! Contains batch processing functionality for high-throughput key retrieval scenarios.

use super::{KeyRetrieverReady, SecureRetrievedKey, StreamConfig};
use crate::{
    KeyError,
    traits::{KeyRetrieval, KeyStorage},
};
use crossbeam_channel::{Receiver, bounded, unbounded};
use zeroize::Zeroize;

/// Batch key retrieval for high-throughput scenarios with security isolation
pub struct KeyRetrieverBatch<S: KeyStorage + KeyRetrieval + Send + Sync + Clone + 'static> {
    pub(crate) retriever: KeyRetrieverReady<S>,
    pub(crate) suffixes: Vec<String>,
    pub(crate) stream_config: StreamConfig,
}

impl<S: KeyStorage + KeyRetrieval + Send + Sync + Clone + 'static> KeyRetrieverReady<S> {
    /// Create batch retriever for multiple keys with same namespace/version
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The suffixes list is empty (must retrieve at least one key)
    /// - The batch count exceeds 1000 keys (security limit)
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
    #[must_use]
    pub fn with_stream_config(mut self, config: StreamConfig) -> Self {
        self.stream_config = config;
        self
    }

    /// Retrieve all keys and stream results securely
    pub fn retrieve_all(self) -> Receiver<Result<SecureRetrievedKey, KeyError>> {
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
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Any individual key retrieval fails (storage errors, key not found, etc.)
    /// - The channel communication fails during batch processing
    /// - Memory allocation fails for the collected keys
    pub fn retrieve_collect(self) -> Result<Vec<SecureRetrievedKey>, KeyError> {
        let count = self.suffixes.len();
        let mut keys = Vec::with_capacity(count);
        let rx = self.retrieve_all();

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
