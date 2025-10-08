//! Handler execution methods for key retrieval

use super::builder_states::KeyRetrieverWithHandler;
use crate::KeyId;
use crate::storage_status::StorageOperationStatus;
use crate::traits::KeyStorage;

impl<S: KeyStorage + crate::traits::KeyRetrieval, F, T> KeyRetrieverWithHandler<S, F, T>
where
    F: FnOnce(crate::Result<Vec<u8>>) -> T + Send + 'static,
    T: cryypt_common::NotResult + Send + 'static,
    S: KeyStorage + crate::traits::KeyRetrieval + Send + 'static,
{
    /// Apply result handler and retrieve key - internal execution method
    /// USERS USE SEXY SYNTAX Ok => result IN CLOSURES - internal macros handle transformation
    /// This method follows EXACT pattern from `AesWithKeyAndHandler::encrypt`
    pub async fn execute<I: Into<String>>(self, key_id: I) -> T {
        let store = self.store;
        let key_id = key_id.into();
        let handler = self.result_handler;

        // Retrieve key securely using the same pattern as AES
        let result = async move {
            // Convert string to SimpleKeyId
            let simple_key_id = crate::SimpleKeyId::new(key_id);

            // Track storage operation status for proper error differentiation
            let mut operation_status = StorageOperationStatus::Success;

            // Retrieve the key securely using real storage backend
            // This follows the README.md async pattern with proper error handling
            let key_bytes = store
                .retrieve(&simple_key_id)
                .on_result(|storage_result| match storage_result {
                    Ok(bytes) => {
                        if bytes.is_empty() {
                            operation_status = StorageOperationStatus::KeyNotFound {
                                key_id: simple_key_id.id().to_string(),
                            };
                        }
                        bytes
                    }
                    Err(storage_error) => {
                        // Classify the storage error based on error message content
                        let error_msg = format!("{storage_error}");
                        operation_status = if error_msg.contains("not found")
                            || error_msg.contains("No such key")
                        {
                            StorageOperationStatus::KeyNotFound {
                                key_id: simple_key_id.id().to_string(),
                            }
                        } else if error_msg.contains("connection") || error_msg.contains("network")
                        {
                            StorageOperationStatus::ConnectionFailed {
                                backend_type: "KeyStorage".to_string(),
                                details: error_msg.clone(),
                            }
                        } else if error_msg.contains("unavailable") || error_msg.contains("timeout")
                        {
                            StorageOperationStatus::Unavailable {
                                reason: error_msg.clone(),
                            }
                        } else {
                            StorageOperationStatus::BackendError {
                                operation: "retrieve".to_string(),
                                details: error_msg,
                            }
                        };

                        // Log the actual storage error for diagnostics with proper classification
                        tracing::error!(
                            "Key retrieval failed for {} with status {:?}: {}",
                            simple_key_id.id(),
                            operation_status,
                            storage_error
                        );

                        // Return empty Vec to be handled below with proper error context
                        Vec::new()
                    }
                })
                .await;

            // Handle result based on operation status and actual data
            if key_bytes.is_empty() {
                // Convert the tracked operation status to appropriate error
                Err(operation_status.to_key_error())
            } else {
                // Comprehensive key validation using existing entropy system
                Self::validate_key_material(&key_bytes).map(|()| key_bytes)
            }
        }
        .await;

        // Apply result handler following AES pattern
        handler(result)
    }

    /// Validate key material using comprehensive cryptographic validation
    /// Uses existing NIST SP 800-90B entropy estimation and security checks
    fn validate_key_material(key_bytes: &[u8]) -> crate::Result<()> {
        // 1. Check for empty keys
        if key_bytes.is_empty() {
            return Err(crate::KeyError::InvalidKeyFormat(
                "Key material cannot be empty".to_string(),
            ));
        }

        // 2. Check minimum key size (at least 128 bits for any cryptographic use)
        if key_bytes.len() < 16 {
            return Err(crate::KeyError::InvalidKeyFormat(format!(
                "Key material too short: {} bytes (minimum 16 bytes)",
                key_bytes.len()
            )));
        }

        // 3. Check for common weak patterns
        if key_bytes.iter().all(|&b| b == 0) {
            return Err(crate::KeyError::InvalidKeyFormat(
                "Key material contains all zeros (placeholder/weak key)".to_string(),
            ));
        }

        if key_bytes.iter().all(|&b| b == 0xFF) {
            return Err(crate::KeyError::InvalidKeyFormat(
                "Key material contains all 0xFF bytes (weak key pattern)".to_string(),
            ));
        }

        // Check for repeating patterns
        if key_bytes.len() > 4 && key_bytes.chunks(4).all(|chunk| chunk == &key_bytes[0..4]) {
            return Err(crate::KeyError::InvalidKeyFormat(
                "Key material contains repeating pattern (weak key)".to_string(),
            ));
        }

        // 4. Use existing NIST SP 800-90B entropy estimation for validation
        let entropy_source = crate::entropy::EntropySource::new().map_err(|e| {
            crate::KeyError::InvalidKeyFormat(format!(
                "Failed to initialize entropy validation: {e}"
            ))
        })?;

        let estimated_entropy = entropy_source.estimate_entropy(key_bytes);

        // Require minimum entropy threshold (from existing entropy system)
        if estimated_entropy < crate::entropy::MIN_ENTROPY_THRESHOLD {
            return Err(crate::KeyError::InvalidKeyFormat(format!(
                "Key material entropy too low: {:.2} bits/byte (minimum {:.2} required)",
                estimated_entropy,
                crate::entropy::MIN_ENTROPY_THRESHOLD
            )));
        }

        // 5. Check for reasonable key sizes for common algorithms
        match key_bytes.len() {
            16 | 24 | 32 => {
                // Valid AES key sizes (128, 192, 256 bits) and ChaCha20 (256 bits)
                Ok(())
            }
            64 => {
                // Valid for some HMAC keys (512 bits)
                Ok(())
            }
            len if (16..=4096).contains(&len) => {
                // Reasonable range for other cryptographic keys
                Ok(())
            }
            len => Err(crate::KeyError::InvalidKeyFormat(format!(
                "Unusual key size: {len} bytes (may indicate corrupted key)"
            ))),
        }
    }

    /// Retrieve key - action takes key ID as argument, follows README.md pattern
    /// USERS USE SEXY SYNTAX Ok => result IN CLOSURES - internal macros handle transformation
    /// This method follows EXACT pattern from `AesWithKeyAndHandler::encrypt`
    pub async fn retrieve<I: Into<String>>(self, key_id: I) -> T {
        self.execute(key_id).await
    }
}
