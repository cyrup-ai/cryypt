//! Key identifier types

use std::fmt;

/// Trait representing a key identifier
pub trait KeyId: Send + Sync + fmt::Debug + fmt::Display {
    /// Get the unique identifier for this key
    fn id(&self) -> &str;

    /// Get the version of this key
    fn version(&self) -> u32 {
        1
    }

    /// Get the optional namespace for this key
    fn namespace(&self) -> Option<&str> {
        None
    }

    /// Get a full identifier string including namespace and version
    fn full_id(&self) -> String {
        match self.namespace() {
            Some(ns) => format!("{}/{}:{}", ns, self.id(), self.version()),
            None => format!("{}:{}", self.id(), self.version()),
        }
    }
}

/// Simple string-based key ID
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SimpleKeyId(String);

impl SimpleKeyId {
    /// Create a new `SimpleKeyId` from a string identifier
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }
}

impl KeyId for SimpleKeyId {
    fn id(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SimpleKeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}
