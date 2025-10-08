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
    pub fn from_serializable<T: Serialize>(value: &T) -> VaultResult<Self> {
        let bytes = serde_json::to_vec(value).map_err(VaultError::Serialization)?;
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
    #[allow(dead_code)]
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
    pub fn to_serializable<T: for<'de> Deserialize<'de>>(&self) -> VaultResult<T> {
        serde_json::from_slice(self.expose_secret()).map_err(VaultError::Serialization)
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

// Full deserialization with version compatibility and metadata support
impl<'de> Deserialize<'de> for VaultValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::{self, MapAccess, Visitor};

        struct VaultValueVisitor;

        impl<'de> Visitor<'de> for VaultValueVisitor {
            type Value = VaultValue;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("VaultValue with version compatibility")
            }

            fn visit_bytes<E>(self, value: &[u8]) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                // Direct bytes - legacy format compatibility
                Ok(VaultValue {
                    inner: Zeroizing::new(value.to_vec()),
                    metadata: None,
                    provider: None,
                    key: None,
                })
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: de::SeqAccess<'de>,
            {
                // Array format - legacy compatibility
                let bytes: Vec<u8> = seq.next_element()?.unwrap_or_default();
                Ok(VaultValue {
                    inner: Zeroizing::new(bytes),
                    metadata: None,
                    provider: None,
                    key: None,
                })
            }

            fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
            where
                M: MapAccess<'de>,
            {
                let mut version: Option<u32> = None;
                let mut value_data: Option<Vec<u8>> = None;
                let mut metadata: Option<serde_json::Value> = None;
                let mut _provider: Option<String> = None;
                let mut key: Option<String> = None;

                while let Some(field_name) = map.next_key::<String>()? {
                    match field_name.as_str() {
                        "version" => version = Some(map.next_value()?),
                        "value" | "inner" | "data" => value_data = Some(map.next_value()?),
                        "metadata" => metadata = Some(map.next_value()?),
                        "provider" => _provider = Some(map.next_value()?),
                        "key" => key = Some(map.next_value()?),
                        _ => {
                            // Skip unknown fields for forward compatibility
                            let _ = map.next_value::<serde_json::Value>()?;
                        }
                    }
                }

                let inner_data = value_data.ok_or_else(|| de::Error::missing_field("value"))?;

                // Version compatibility check
                if let Some(v) = version
                    && v > 2
                {
                    return Err(de::Error::custom(format!(
                        "Unsupported VaultValue version: {}",
                        v
                    )));
                }

                Ok(VaultValue {
                    inner: Zeroizing::new(inner_data),
                    metadata,
                    provider: None, // Provider cannot be deserialized from string
                    key,
                })
            }
        }

        deserializer.deserialize_any(VaultValueVisitor)
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
