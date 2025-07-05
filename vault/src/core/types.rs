//! Core vault types
//!
//! Contains the main VaultValue type and related implementations for secure value storage.

use crate::error::{VaultError, VaultResult};
use crate::operation::VaultOperation;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use zeroize::{Zeroize, Zeroizing};

/// Represents a value stored in the vault, ensuring the underlying bytes are zeroized.
/// Includes support for metadata, provider tracking, and secure serialization.
/// Use helper methods like `from_string`, `from_serializable`, `expose_as_str`, `to_serializable`
/// for common conversions.
#[derive(Clone)]
pub struct VaultValue {
    inner: Zeroizing<Vec<u8>>,
    metadata: Option<serde_json::Value>,
    provider: Option<Arc<dyn VaultOperation + Send + Sync>>,
    key: Option<String>,
}

// --- VaultValue Implementations ---

impl VaultValue {
    /// Creates a VaultValue from raw bytes.
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self {
            inner: Zeroizing::new(bytes),
            metadata: None,
            provider: None,
            key: None,
        }
    }

    /// Creates a VaultValue from a String (converts to UTF-8 bytes).
    pub fn from_string(s: String) -> Self {
        Self {
            inner: Zeroizing::new(s.into_bytes()),
            metadata: None,
            provider: None,
            key: None,
        }
    }

    /// Creates a VaultValue by serializing a type `T` to JSON bytes.
    pub fn from_serializable<T: Serialize>(value: &T) -> Result<Self, VaultError> {
        let bytes = serde_json::to_vec(value).map_err(|e| VaultError::Serialization(e))?;
        Ok(Self {
            inner: Zeroizing::new(bytes),
            metadata: None,
            provider: None,
            key: None,
        })
    }

    /// Adds metadata to a VaultValue
    pub fn with_metadata(mut self, metadata: HashMap<String, String>) -> Self {
        let metadata_value = serde_json::Value::Object(
            metadata
                .into_iter()
                .map(|(k, v)| (k, serde_json::Value::String(v)))
                .collect(),
        );
        self.metadata = Some(metadata_value);
        self
    }

    /// Sets the associated key and provider for this value
    pub(crate) fn with_provider(
        mut self,
        key: String,
        provider: Arc<dyn VaultOperation + Send + Sync>,
    ) -> Self {
        self.key = Some(key);
        self.provider = Some(provider);
        self
    }

    /// Returns the metadata if present
    pub fn metadata(&self) -> Option<&serde_json::Value> {
        self.metadata.as_ref()
    }

    /// Exposes the underlying bytes temporarily. Use with caution.
    pub fn expose_secret(&self) -> &[u8] {
        &self.inner
    }

    /// Tries to interpret the bytes as a UTF-8 string, exposing temporarily.
    pub fn expose_as_str(&self) -> Result<&str, std::str::Utf8Error> {
        std::str::from_utf8(self.expose_secret())
    }

    /// Tries to deserialize the underlying bytes (assuming JSON) into type `T`.
    pub fn to_serializable<T: for<'de> Deserialize<'de>>(&self) -> Result<T, VaultError> {
        serde_json::from_slice(self.expose_secret()).map_err(|e| VaultError::Serialization(e))
    }

    /// Consumes the VaultValue and returns the inner Zeroizing<Vec<u8>>.
    pub fn into_secret_bytes(self) -> Zeroizing<Vec<u8>> {
        self.inner
    }
}

// --- Zeroize Implementation ---

impl Zeroize for VaultValue {
    fn zeroize(&mut self) {
        self.inner.zeroize();
        // No need to zeroize other fields as they don't contain sensitive data
    }
}

// --- Serialize / Deserialize Implementations ---
// Implementation for secure serialization with redaction

impl Serialize for VaultValue {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("VaultValue", 3)?;
        state.serialize_field("value", "<redacted>")?; // Always redact value
        if let Some(metadata) = &self.metadata {
            state.serialize_field("metadata", metadata)?;
        }
        if let Some(key) = &self.key {
            state.serialize_field("key", key)?;
        }
        state.end()
    }
}

// We only deserialize the inner SecretBytes for now
// Full deserialization with metadata support could be added later if needed
impl<'de> Deserialize<'de> for VaultValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        let inner = Zeroizing::new(bytes);
        Ok(VaultValue {
            inner,
            metadata: None,
            provider: None,
            key: None,
        })
    }
}

// Implement Debug that redacts the sensitive content
impl fmt::Debug for VaultValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug_struct = f.debug_struct("VaultValue");
        debug_struct.field("value", &"<redacted>"); // Always redact sensitive value
        if let Some(metadata) = &self.metadata {
            debug_struct.field("metadata", metadata);
        }
        if let Some(key) = &self.key {
            debug_struct.field("key", key);
        }
        // Avoid debugging the provider directly to prevent potential leaks
        debug_struct.field("provider", &self.provider.as_ref().map(|_| "<provider>"));
        debug_struct.finish()
    }
}