//! Version range retrieval operations
//!
//! Contains functionality for retrieving multiple key versions for key rotation scenarios.

use super::{KeyRetrieverReady, SecureRetrievedKey, StreamConfig};
use crate::{
    KeyError,
    traits::{KeyRetrieval, KeyStorage},
};
use crossbeam_channel::{Receiver, bounded, unbounded};
use zeroize::Zeroize;

/// Version range retrieval for key rotation scenarios
pub struct KeyRetrieverVersionRange<S: KeyStorage + KeyRetrieval + Send + Sync + Clone + 'static> {
    pub(crate) base: KeyRetrieverReady<S>,
    pub(crate) start_version: u32,
    pub(crate) end_version: u32,
    pub(crate) stream_config: StreamConfig,
}

impl<S: KeyStorage + KeyRetrieval + Send + Sync + Clone + 'static> KeyRetrieverReady<S> {
    /// Retrieve all versions in range
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Start or end version is zero (versions must be non-zero)
    /// - Start version is greater than end version
    /// - Version range exceeds 100 versions (security limit)
    #[inline]
    pub fn retrieve_versions(
        self,
        start_version: u32,
        end_version: u32,
    ) -> Result<KeyRetrieverVersionRange<S>, KeyError> {
        if start_version == 0 || end_version == 0 {
            return Err(KeyError::invalid_key("Versions must be non-zero"));
        }
        if start_version > end_version {
            return Err(KeyError::invalid_key(
                "Start version must be <= end version",
            ));
        }
        if end_version - start_version > 100 {
            return Err(KeyError::invalid_key("Version range too large (max 100)"));
        }

        Ok(KeyRetrieverVersionRange {
            base: self,
            start_version,
            end_version,
            stream_config: StreamConfig::bounded((end_version - start_version + 1) as usize),
        })
    }
}

impl<S: KeyStorage + KeyRetrieval + Send + Sync + Clone + 'static> KeyRetrieverVersionRange<S> {
    /// Configure the stream for version range retrieval
    #[inline]
    #[must_use]
    pub fn with_stream_config(mut self, config: StreamConfig) -> Self {
        self.stream_config = config;
        self
    }

    /// Retrieve all versions in range and stream results
    pub fn retrieve_all(self) -> Receiver<Result<SecureRetrievedKey, KeyError>> {
        let (tx, rx) = if self.stream_config.bounded {
            bounded(self.stream_config.capacity)
        } else {
            unbounded()
        };

        let base = self.base;
        let start = self.start_version;
        let end = self.end_version;

        tokio::spawn(async move {
            for version in start..=end {
                // Create retriever for each version
                let r = KeyRetrieverReady {
                    store: base.store.clone(),
                    namespace: base.namespace.clone(),
                    version,
                };

                let key_id = r.generate_key_id(None);
                let result = r.retrieve_internal(&key_id).await;

                if tx.send(result).is_err() {
                    // Receiver dropped
                    break;
                }
            }
        });

        rx
    }

    /// Retrieve all versions and collect into Vec
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Any individual key version retrieval fails (storage errors, key not found, etc.)
    /// - Channel communication fails during version processing
    /// - Memory allocation fails for the collected keys
    pub fn retrieve_collect(self) -> Result<Vec<SecureRetrievedKey>, KeyError> {
        let count = (self.end_version - self.start_version + 1) as usize;
        let mut keys = Vec::with_capacity(count);
        let rx = self.retrieve_all();

        for _ in 0..count {
            match rx.recv() {
                Ok(Ok(key)) => keys.push(key),
                Ok(Err(e)) => {
                    for key in &mut keys {
                        key.data.zeroize();
                    }
                    return Err(e);
                }
                Err(_) => {
                    for key in &mut keys {
                        key.data.zeroize();
                    }
                    return Err(KeyError::internal(
                        "Channel disconnected during version range retrieval",
                    ));
                }
            }
        }

        Ok(keys)
    }
}
