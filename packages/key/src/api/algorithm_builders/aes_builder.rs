//! AES Key Builder - Polymorphic pattern for AES key operations
//!
//! Integrates with existing `KeyGenerator` system while providing polymorphic
//! builder pattern that matches cipher module design.

// Removed unused imports after fixing redundant field names
use futures::Stream;
use rand::RngCore;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;

/// AES key builder - initial state
#[derive(Debug, Clone, Copy)]
pub struct AesKeyBuilder;

/// AES key builder with size configured
#[derive(Debug, Clone, Copy)]
pub struct AesKeyWithSize {
    size_bits: u32,
}

/// AES key builder with size and result handler
#[derive(Debug)]
pub struct AesKeyWithSizeAndHandler<F> {
    size_bits: u32,
    handler: F,
}

/// AES key builder with size and chunk handler for streaming
#[derive(Debug)]
pub struct AesKeyWithSizeAndChunkHandler<F> {
    size_bits: u32,
    handler: F,
}

impl Default for AesKeyBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl AesKeyBuilder {
    /// Create new AES key builder
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl AesKeyWithSize {
    /// Set result handler for single key generation
    pub fn on_result<F, T>(self, handler: F) -> AesKeyWithSizeAndHandler<F>
    where
        F: FnOnce(crate::Result<Vec<u8>>) -> T,
        T: cryypt_common::NotResult,
    {
        AesKeyWithSizeAndHandler {
            size_bits: self.size_bits,
            handler,
        }
    }

    /// Set chunk handler for batch key generation
    pub fn on_chunk<F>(self, handler: F) -> AesKeyWithSizeAndChunkHandler<F>
    where
        F: Fn(crate::Result<Vec<u8>>) -> Vec<u8>,
    {
        AesKeyWithSizeAndChunkHandler {
            size_bits: self.size_bits,
            handler,
        }
    }
}

impl AesKeyBuilder {
    /// Set AES key size (128, 192, or 256 bits)
    #[must_use]
    pub fn with_size(self, size_bits: u32) -> AesKeyWithSize {
        AesKeyWithSize { size_bits }
    }
}

impl<F, T> AesKeyWithSizeAndHandler<F>
where
    F: FnOnce(crate::Result<Vec<u8>>) -> T + Send + 'static,
    T: cryypt_common::NotResult + Send + 'static,
{
    /// Generate single AES key
    pub async fn generate(self) -> T {
        let result = async {
            // Validate AES key size
            if !matches!(self.size_bits, 128 | 192 | 256) {
                return Err(crate::error::KeyError::InvalidKeySize {
                    expected: 256,
                    actual: self.size_bits as usize,
                });
            }

            // Generate secure AES key
            let size_bytes = (self.size_bits / 8) as usize;
            let mut key_bytes = vec![0u8; size_bytes];

            // Use secure random generation
            let mut rng = rand::rng();
            rng.fill_bytes(&mut key_bytes);

            Ok(key_bytes)
        }
        .await;

        // Apply result handler
        (self.handler)(result)
    }
}

impl<F> AesKeyWithSizeAndChunkHandler<F>
where
    F: Fn(crate::Result<Vec<u8>>) -> Vec<u8> + Send + 'static,
{
    /// Generate batch of AES keys as stream
    pub fn generate_batch(self, count: usize) -> impl Stream<Item = Vec<u8>> {
        let (tx, rx) = mpsc::channel(32);
        let size_bits = self.size_bits;
        let handler = self.handler;

        tokio::spawn(async move {
            for i in 0..count {
                // Yield control to allow other tasks to run
                tokio::task::yield_now().await;

                // Generate individual key using same logic as single generation
                let result = async {
                    // Validate key size
                    if !matches!(size_bits, 128 | 192 | 256) {
                        return Err(crate::error::KeyError::InvalidKeySize {
                            expected: 256,
                            actual: size_bits as usize,
                        });
                    }

                    // Generate secure AES key
                    let size_bytes = (size_bits / 8) as usize;
                    let mut key_bytes = vec![0u8; size_bytes];

                    // Use secure random generation
                    let mut rng = rand::rng();
                    rng.fill_bytes(&mut key_bytes);

                    Ok(key_bytes)
                }
                .await;

                // Apply handler and send result
                let processed_key = handler(result);

                if tx.send(processed_key).await.is_err() {
                    break; // Receiver dropped
                }

                // Log progress for batch operations
                if (i + 1) % 10 == 0 {
                    log::debug!("Generated {} AES keys", i + 1);
                }
            }
        });

        ReceiverStream::new(rx)
    }
}
