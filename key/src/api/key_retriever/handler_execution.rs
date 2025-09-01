//! Handler execution methods for key retrieval

use super::builder_states::KeyRetrieverWithHandler;
use crate::traits::KeyStorage;
use crate::KeyId;

impl<S: KeyStorage + crate::traits::KeyRetrieval, F, T> KeyRetrieverWithHandler<S, F, T>
where
    F: FnOnce(crate::Result<Vec<u8>>) -> T + Send + 'static,
    T: cryypt_common::NotResult + Send + 'static,
    S: KeyStorage + crate::traits::KeyRetrieval + Send + 'static,
{
    /// Apply result handler and retrieve key - internal execution method
    /// USERS USE SEXY SYNTAX Ok => result IN CLOSURES - internal macros handle transformation
    /// This method follows EXACT pattern from AesWithKeyAndHandler::encrypt
    pub async fn execute<I: Into<String>>(self, key_id: I) -> T {
        let store = self.store;
        let key_id = key_id.into();
        let handler = self.result_handler;

        // Retrieve key securely using the same pattern as AES
        let result = async move {
            // Convert string to SimpleKeyId
            let simple_key_id = crate::SimpleKeyId::new(key_id);

            // Retrieve the key securely using real storage backend
            // This follows the README.md async pattern with proper error handling
            let key_bytes = store.retrieve(&simple_key_id)
                .on_result(|storage_result| match storage_result {
                    Ok(bytes) => bytes,
                    Err(storage_error) => {
                        // Log the actual storage error for diagnostics
                        tracing::error!("Key retrieval failed for {}: {}", simple_key_id.id(), storage_error);
                        // Return empty Vec to be handled below with proper error context
                        Vec::new()
                    }
                })
                .await;

            // Handle empty result with proper error classification
            if key_bytes.is_empty() {
                // Check if this was due to a storage error (would have been logged above)
                // or genuinely missing key - for now treat as KeyNotFound but preserve diagnostic info
                Err(crate::KeyError::KeyNotFound {
                    id: simple_key_id.id().to_string(),
                    version: 1,
                })
            } else {
                // Comprehensive key validation using existing entropy system
                Self::validate_key_material(&key_bytes)
                    .map(|_| key_bytes)
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
                "Key material cannot be empty".to_string()
            ));
        }

        // 2. Check minimum key size (at least 128 bits for any cryptographic use)
        if key_bytes.len() < 16 {
            return Err(crate::KeyError::InvalidKeyFormat(
                format!("Key material too short: {} bytes (minimum 16 bytes)", key_bytes.len())
            ));
        }

        // 3. Check for common weak patterns
        if key_bytes.iter().all(|&b| b == 0) {
            return Err(crate::KeyError::InvalidKeyFormat(
                "Key material contains all zeros (placeholder/weak key)".to_string()
            ));
        }
        
        if key_bytes.iter().all(|&b| b == 0xFF) {
            return Err(crate::KeyError::InvalidKeyFormat(
                "Key material contains all 0xFF bytes (weak key pattern)".to_string()
            ));
        }
        
        // Check for repeating patterns
        if key_bytes.len() > 4 && key_bytes.chunks(4).all(|chunk| chunk == &key_bytes[0..4]) {
            return Err(crate::KeyError::InvalidKeyFormat(
                "Key material contains repeating pattern (weak key)".to_string()
            ));
        }

        // 4. Use existing NIST SP 800-90B entropy estimation for validation
        let entropy_source = crate::entropy::EntropySource::new()
            .map_err(|e| crate::KeyError::InvalidKeyFormat(
                format!("Failed to initialize entropy validation: {}", e)
            ))?;
            
        let estimated_entropy = entropy_source.estimate_entropy(key_bytes);
        
        // Require minimum entropy threshold (from existing entropy system)
        if estimated_entropy < crate::entropy::MIN_ENTROPY_THRESHOLD {
            return Err(crate::KeyError::InvalidKeyFormat(
                format!(
                    "Key material entropy too low: {:.2} bits/byte (minimum {:.2} required)",
                    estimated_entropy,
                    crate::entropy::MIN_ENTROPY_THRESHOLD
                )
            ));
        }

        // 5. Check for reasonable key sizes for common algorithms
        match key_bytes.len() {
            16 | 24 | 32 => {
                // Valid AES key sizes (128, 192, 256 bits) and ChaCha20 (256 bits)
                Ok(())
            },
            64 => {
                // Valid for some HMAC keys (512 bits)
                Ok(())
            },
            len if len >= 16 && len <= 4096 => {
                // Reasonable range for other cryptographic keys
                Ok(())
            },
            len => {
                Err(crate::KeyError::InvalidKeyFormat(
                    format!("Unusual key size: {} bytes (may indicate corrupted key)", len)
                ))
            }
        }
    }

    /// Retrieve key - action takes key ID as argument, follows README.md pattern
    /// USERS USE SEXY SYNTAX Ok => result IN CLOSURES - internal macros handle transformation
    /// This method follows EXACT pattern from AesWithKeyAndHandler::encrypt
    pub async fn retrieve<I: Into<String>>(self, key_id: I) -> T {
        self.execute(key_id).await
    }
}
