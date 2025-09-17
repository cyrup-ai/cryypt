//! Ready state methods for key retrieval operations

use super::builder_states::{KeyRetrieverReady, KeyRetrieverWithHandler};
use crate::{SimpleKeyId, traits::KeyStorage};

impl<S: KeyStorage> KeyRetrieverReady<S> {
    /// Generate secure key identifier matching `KeyGenerator` pattern
    #[inline]
    pub(crate) fn generate_key_id(&self, unique_suffix: Option<&str>) -> SimpleKeyId {
        match unique_suffix {
            Some(suffix) => {
                SimpleKeyId::new(format!("{}:v{}:{}", self.namespace, self.version, suffix))
            }
            None => SimpleKeyId::new(format!("{}:v{}", self.namespace, self.version)),
        }
    }

    /// Get the configured namespace
    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    /// Get the configured version
    pub const fn version(&self) -> u32 {
        self.version
    }

    /// Retrieve key with default unwrapping - README.md pattern
    /// Returns unwrapped Vec<u8> with default error handling (empty Vec on error)
    pub async fn retrieve<I: Into<String>>(self, key_id: I) -> Vec<u8>
    where
        S: crate::traits::KeyRetrieval,
    {
        let store = self.store;
        let key_id = key_id.into();

        // Convert string to SimpleKeyId
        let simple_key_id = crate::SimpleKeyId::new(key_id);

        // Retrieve key using storage backend with default unwrapping
        store
            .retrieve(&simple_key_id)
            .on_result(|result: crate::Result<Vec<u8>>| result.unwrap_or_default())
            .await
    }

    /// Add `on_result` handler - README.md pattern with sexy syntax support
    /// USERS WRITE: Ok => result, Err(e) => `Vec::new()` - CRATE PRIVATE macros transform it
    /// This method signature follows EXACT pattern from `AesWithKey.on_result`
    pub fn on_result<F, T>(self, handler: F) -> KeyRetrieverWithHandler<S, F, T>
    where
        F: FnOnce(crate::Result<Vec<u8>>) -> T + Send + 'static,
        T: cryypt_common::NotResult + Send + 'static,
    {
        KeyRetrieverWithHandler {
            store: self.store,
            namespace: self.namespace,
            version: self.version,
            result_handler: handler,
            _phantom: std::marker::PhantomData,
        }
    }
}
