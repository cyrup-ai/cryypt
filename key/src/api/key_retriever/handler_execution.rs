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
                .on_result(|storage_result| storage_result.unwrap_or_default())
                .await;

            // Validate retrieved key material and convert to proper Result
            if key_bytes.is_empty() {
                Err(crate::KeyError::KeyNotFound {
                    id: simple_key_id.id().to_string(),
                    version: 1,
                })
            } else if key_bytes.iter().all(|&b| b == 0) {
                // Detect and reject placeholder/fake keys (all zeros)
                Err(crate::KeyError::InvalidKeyFormat(
                    "Key retrieval returned placeholder/fake key material".to_string()
                ))
            } else {
                // Return validated key material
                Ok(key_bytes)
            }
        }
        .await;

        // Apply result handler following AES pattern
        handler(result)
    }

    /// Retrieve key - action takes key ID as argument, follows README.md pattern
    /// USERS USE SEXY SYNTAX Ok => result IN CLOSURES - internal macros handle transformation
    /// This method follows EXACT pattern from AesWithKeyAndHandler::encrypt
    pub async fn retrieve<I: Into<String>>(self, key_id: I) -> T {
        self.execute(key_id).await
    }
}
