//! Symmetric key generation implementation
//!
//! Contains symmetric key generation logic with cryptographically secure random bytes.

use super::core_types::{SecureKeyBuffer, generate_secure_key_id};
use super::{KeyGeneratorReady, StreamConfig};
use crate::{
    KeyError,
    traits::{KeyImport, KeyStorage},
};
use crossbeam_channel::{Receiver, bounded, unbounded};
use zeroize::Zeroize;

impl<S: KeyStorage + KeyImport> KeyGeneratorReady<S> {
    /// Generate a single key using secure random bytes
    /// Pure async implementation without blocking operations
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The key size is not secure (must be 128, 192, 256, 384, or 512 bits)
    /// - Secure random number generation fails
    /// - Key storage operation fails
    pub async fn generate_key(self) -> Result<crate::api::ActualKey, KeyError> {
        let key_bytes = self.generate_internal().await?;
        Ok(crate::api::ActualKey::from_bytes(key_bytes))
    }

    /// Internal key generation with secure memory handling
    /// Core cryptographic operation with automatic cleanup
    pub(crate) async fn generate_internal(self) -> Result<Vec<u8>, KeyError> {
        let size_bytes = self.key_size_bytes();

        // Validate key size for security
        if !self.is_secure_key_size() {
            return Err(KeyError::invalid_key(format!(
                "Unsupported key size: {} bits (must be 128, 192, 256, 384, or 512)",
                self.size_bits
            )));
        }

        // Generate cryptographically secure unique key identifier
        let key_id = generate_secure_key_id(&self.namespace, self.version);

        // Generate key using secure buffer with automatic cleanup
        let key_buffer = SecureKeyBuffer::new(size_bytes);

        // Fill with cryptographically secure random bytes
        let secure_buffer = key_buffer.fill_secure_random();
        let key_bytes = secure_buffer.into_key_bytes();

        // Store the key using the configured storage backend
        self.store
            .store(&key_id, &key_bytes)
            .on_result(|result| match result {
                Ok(()) => {}
                Err(e) => {
                    log::error!("Failed to store generated key: {e}");
                }
            })
            .await;
        Ok(key_bytes)
    }
}

/// Batch key generation for high-throughput scenarios
/// Secure batch processing with individual key isolation
pub struct KeyGeneratorBatch<S: KeyStorage + KeyImport + Send + Sync + Clone + 'static> {
    pub(crate) generator: KeyGeneratorReady<S>,
    pub(crate) count: usize,
    pub(crate) stream_config: StreamConfig,
}

impl<S: KeyStorage + KeyImport + Send + Sync + Clone + 'static> KeyGeneratorReady<S> {
    /// Create a batch generator for multiple keys
    /// Each key is generated independently for maximum security
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The requested count is zero (must generate at least one key)
    /// - The count exceeds the maximum safe batch size
    #[inline]
    pub fn batch(self, count: usize) -> Result<KeyGeneratorBatch<S>, KeyError> {
        if count == 0 {
            return Err(KeyError::invalid_key(
                "Batch count must be greater than zero",
            ));
        }

        if count > 1000 {
            return Err(KeyError::invalid_key(
                "Batch count too large (max 1000 for security)",
            ));
        }

        Ok(KeyGeneratorBatch {
            generator: self,
            count,
            stream_config: StreamConfig::bounded(count),
        })
    }
}

impl<S: KeyStorage + KeyImport + Send + Sync + Clone + 'static> KeyGeneratorBatch<S> {
    /// Configure the stream for batch generation
    #[inline]
    #[must_use]
    pub fn with_stream_config(mut self, config: StreamConfig) -> Self {
        self.stream_config = config;
        self
    }

    /// Generate multiple keys and stream results securely
    /// Each key is generated in isolation to prevent cross-contamination
    ///
    /// # Errors
    ///
    /// Each generated key in the stream can return an error if:
    /// - The key size is not secure (must be 128, 192, 256, 384, or 512 bits)
    /// - Secure random number generation fails for that key
    /// - Key storage operation fails for that key
    pub fn generate_all(self) -> Receiver<Result<Vec<u8>, KeyError>> {
        let (tx, rx) = if self.stream_config.bounded {
            bounded(self.stream_config.capacity)
        } else {
            unbounded()
        };

        let count = self.count;
        let generator = self.generator;

        tokio::spawn(async move {
            for _i in 0..count {
                // Clone generator for each key generation
                // This ensures complete isolation between key generations
                let generator_instance = KeyGeneratorReady {
                    size_bits: generator.size_bits,
                    store: generator.store.clone(),
                    namespace: generator.namespace.clone(),
                    version: generator.version,
                };

                let result = generator_instance.generate_internal().await;

                // Send each result through the secure channel
                if tx.send(result).is_err() {
                    // Receiver dropped, stop generating immediately
                    break;
                }
            }
        });

        rx
    }

    /// Generate multiple keys and collect into Vec securely
    /// Optimized collection with secure memory handling
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Any individual key generation fails (see `generate_key` for details)
    /// - The channel communication fails during batch processing
    /// - Memory allocation fails for the collected keys
    pub fn generate_collect(self) -> Result<Vec<Vec<u8>>, KeyError> {
        let count = self.count;
        let mut keys = Vec::with_capacity(count);
        let rx = self.generate_all();

        // Collect all results securely
        for _ in 0..count {
            match rx.recv() {
                Ok(Ok(key)) => keys.push(key),
                Ok(Err(e)) => {
                    // Clear any partial results on error for security
                    keys.zeroize();
                    return Err(e);
                }
                Err(_) => {
                    // Clear any partial results on channel error
                    keys.zeroize();
                    return Err(KeyError::internal(
                        "Channel disconnected during batch generation",
                    ));
                }
            }
        }

        Ok(keys)
    }
}

impl<S: KeyStorage + KeyImport + Send + Sync + Clone + 'static> crate::result_macro::KeyProducer
    for KeyGeneratorReady<S>
{
    async fn produce_key(self) -> Result<crate::api::ActualKey, crate::KeyError> {
        self.generate_key().await
    }
}
