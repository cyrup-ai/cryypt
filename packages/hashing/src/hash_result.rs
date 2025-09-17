//! Hash result type with encoding support

/// Result of a hash operation with encoding options
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HashResult {
    /// Raw hash bytes
    bytes: Vec<u8>,
}

impl HashResult {
    /// Create a new hash result from raw bytes
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Get the raw bytes of the hash
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Convert to a Vec<u8>
    #[must_use]
    pub fn to_vec(self) -> Vec<u8> {
        self.bytes
    }

    /// Get the hash as a hexadecimal string
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(&self.bytes)
    }

    /// Get the hash as a base64 string
    #[must_use]
    pub fn to_base64(&self) -> String {
        use base64::{Engine as _, engine::general_purpose};
        general_purpose::STANDARD.encode(&self.bytes)
    }

    /// Get the hash as a base64url string (URL-safe)
    #[must_use]
    pub fn to_base64url(&self) -> String {
        base64_url::encode(&self.bytes)
    }

    /// Get the length of the hash in bytes
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Check if the hash is empty
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

impl From<Vec<u8>> for HashResult {
    fn from(bytes: Vec<u8>) -> Self {
        Self::new(bytes)
    }
}

impl From<HashResult> for Vec<u8> {
    fn from(result: HashResult) -> Self {
        result.bytes
    }
}

impl AsRef<[u8]> for HashResult {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl std::fmt::Display for HashResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}
