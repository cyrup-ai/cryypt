//! RSA Key Builder - Polymorphic pattern for RSA keypair operations
//!
//! Integrates with existing `KeyGenerator` system while providing polymorphic
//! builder pattern for RSA keypair generation.

// Removed unused imports after fixing redundant field names
use futures::Stream;
use rand::rng;
use rsa::pkcs1::{EncodeRsaPrivateKey, EncodeRsaPublicKey};
use rsa::{RsaPrivateKey, RsaPublicKey};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;

/// RSA key builder - initial state
#[derive(Debug, Clone, Copy)]
pub struct RsaKeyBuilder;

/// RSA key builder with size configured
#[derive(Debug, Clone, Copy)]
pub struct RsaKeyWithSize {
    size_bits: u32,
}

/// RSA key builder with size and result handler
#[derive(Debug)]
pub struct RsaKeyWithSizeAndHandler<F> {
    size_bits: u32,
    handler: F,
}

/// RSA key builder with size and chunk handler for streaming
#[derive(Debug)]
pub struct RsaKeyWithSizeAndChunkHandler<F> {
    size_bits: u32,
    handler: F,
}

impl Default for RsaKeyBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl RsaKeyBuilder {
    /// Create new RSA key builder
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Set RSA key size (2048 or 4096 bits)
    #[must_use]
    pub fn with_size(self, size_bits: u32) -> RsaKeyWithSize {
        RsaKeyWithSize { size_bits }
    }
}

impl RsaKeyWithSize {
    /// Set result handler for single keypair generation
    pub fn on_result<F, T>(self, handler: F) -> RsaKeyWithSizeAndHandler<F>
    where
        F: FnOnce(crate::Result<Vec<u8>>) -> T,
        T: cryypt_common::NotResult,
    {
        RsaKeyWithSizeAndHandler {
            size_bits: self.size_bits,
            handler,
        }
    }

    /// Set chunk handler for batch keypair generation
    pub fn on_chunk<F>(self, handler: F) -> RsaKeyWithSizeAndChunkHandler<F>
    where
        F: Fn(crate::Result<Vec<u8>>) -> Vec<u8>,
    {
        RsaKeyWithSizeAndChunkHandler {
            size_bits: self.size_bits,
            handler,
        }
    }
}

impl<F, T> RsaKeyWithSizeAndHandler<F>
where
    F: FnOnce(crate::Result<Vec<u8>>) -> T + Send + 'static,
    T: cryypt_common::NotResult + Send + 'static,
{
    /// Generate single RSA keypair
    pub async fn generate(self) -> T {
        let result = async {
            // Validate RSA key size
            if !matches!(self.size_bits, 2048 | 4096) {
                return Err(crate::error::KeyError::InvalidKeySize {
                    expected: 2048,
                    actual: self.size_bits as usize,
                });
            }

            // Generate real RSA keypair using production RSA library
            let mut rng = rng();
            let private_key =
                RsaPrivateKey::new(&mut rng, self.size_bits as usize).map_err(|e| {
                    crate::error::KeyError::KeyGeneration(format!("RSA key generation failed: {e}"))
                })?;

            let public_key = RsaPublicKey::from(&private_key);

            // Encode keys to DER format and combine
            let private_der = private_key
                .to_pkcs1_der()
                .map_err(|e| {
                    crate::error::KeyError::InvalidKeyFormat(format!(
                        "Private key encoding failed: {e}"
                    ))
                })?
                .as_bytes()
                .to_vec();

            let public_der = public_key
                .to_pkcs1_der()
                .map_err(|e| {
                    crate::error::KeyError::InvalidKeyFormat(format!(
                        "Public key encoding failed: {e}"
                    ))
                })?
                .as_bytes()
                .to_vec();

            // Combine private and public key bytes with length prefixes for parsing
            let mut keypair_bytes = Vec::new();

            // Convert lengths safely, ensuring no truncation
            let private_len = u32::try_from(private_der.len()).map_err(|_| {
                crate::error::KeyError::Internal("Private key too large".to_string())
            })?;
            let public_len = u32::try_from(public_der.len()).map_err(|_| {
                crate::error::KeyError::Internal("Public key too large".to_string())
            })?;

            keypair_bytes.extend_from_slice(&private_len.to_le_bytes());
            keypair_bytes.extend_from_slice(&private_der);
            keypair_bytes.extend_from_slice(&public_len.to_le_bytes());
            keypair_bytes.extend_from_slice(&public_der);

            Ok(keypair_bytes)
        }
        .await;

        // Apply result handler
        (self.handler)(result)
    }
}

impl<F> RsaKeyWithSizeAndChunkHandler<F>
where
    F: Fn(crate::Result<Vec<u8>>) -> Vec<u8> + Send + 'static,
{
    /// Generate batch of RSA keypairs as stream
    pub fn generate_batch(self, count: usize) -> impl Stream<Item = Vec<u8>> {
        let (tx, rx) = mpsc::channel(32);
        let size_bits = self.size_bits;
        let handler = self.handler;

        tokio::spawn(async move {
            for i in 0..count {
                // Yield control to allow other tasks to run
                tokio::task::yield_now().await;

                // Generate individual RSA keypair
                let result = async {
                    use rand::rng;
                    use rsa::pkcs1::{EncodeRsaPrivateKey, EncodeRsaPublicKey};
                    use rsa::{RsaPrivateKey, RsaPublicKey};

                    // Validate RSA key size
                    if !matches!(size_bits, 2048 | 4096) {
                        return Err(crate::error::KeyError::InvalidKeySize {
                            expected: 2048,
                            actual: size_bits as usize,
                        });
                    }

                    // Generate real RSA keypair using production RSA library

                    let mut rng = rng();
                    let private_key =
                        RsaPrivateKey::new(&mut rng, size_bits as usize).map_err(|e| {
                            crate::error::KeyError::KeyGeneration(format!(
                                "RSA key generation failed: {e}"
                            ))
                        })?;

                    let public_key = RsaPublicKey::from(&private_key);

                    // Encode keys to DER format and combine
                    let private_der = private_key
                        .to_pkcs1_der()
                        .map_err(|e| {
                            crate::error::KeyError::InvalidKeyFormat(format!(
                                "Private key encoding failed: {e}"
                            ))
                        })?
                        .as_bytes()
                        .to_vec();

                    let public_der = public_key
                        .to_pkcs1_der()
                        .map_err(|e| {
                            crate::error::KeyError::InvalidKeyFormat(format!(
                                "Public key encoding failed: {e}"
                            ))
                        })?
                        .as_bytes()
                        .to_vec();

                    // Combine private and public key bytes with length prefixes for parsing
                    let mut keypair_bytes = Vec::new();

                    // Convert lengths safely, ensuring no truncation
                    let private_len = u32::try_from(private_der.len()).map_err(|_| {
                        crate::error::KeyError::Internal("Private key too large".to_string())
                    })?;
                    let public_len = u32::try_from(public_der.len()).map_err(|_| {
                        crate::error::KeyError::Internal("Public key too large".to_string())
                    })?;

                    keypair_bytes.extend_from_slice(&private_len.to_le_bytes());
                    keypair_bytes.extend_from_slice(&private_der);
                    keypair_bytes.extend_from_slice(&public_len.to_le_bytes());
                    keypair_bytes.extend_from_slice(&public_der);

                    Ok(keypair_bytes)
                }
                .await;

                // Apply handler and send result
                let processed_keypair = handler(result);

                if tx.send(processed_keypair).await.is_err() {
                    break; // Receiver dropped
                }

                // Log progress for batch operations (RSA generation is slower)
                if (i + 1) % 5 == 0 {
                    log::debug!("Generated {} RSA keypairs", i + 1);
                }
            }
        });

        ReceiverStream::new(rx)
    }
}
