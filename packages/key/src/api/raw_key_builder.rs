//! Raw key builder

use crate::{traits::KeyProviderBuilder, KeyResult};

/// Builder for raw key bytes
pub struct RawKeyBuilder {
    key: Vec<u8>,
}

impl RawKeyBuilder {
    /// Create from raw bytes
    pub fn from_bytes(key: Vec<u8>) -> Self {
        Self { key }
    }
}

impl KeyProviderBuilder for RawKeyBuilder {
    fn resolve(&self) -> KeyResult {
        let key = self.key.clone();
        KeyResult::ready(Ok(key))
    }
}
