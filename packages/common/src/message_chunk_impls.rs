//! MessageChunk wrapper types for basic types used throughout cryypt

use cyrup_sugars::prelude::MessageChunk;

/// Wrapper for Vec<u8> that implements MessageChunk
#[derive(Debug, Clone)]
pub struct BytesChunk {
    pub data: Vec<u8>,
    error: Option<String>,
}

impl BytesChunk {
    pub fn new(data: Vec<u8>) -> Self {
        Self { data, error: None }
    }

    pub fn into_inner(self) -> Vec<u8> {
        self.data
    }
}

impl MessageChunk for BytesChunk {
    fn bad_chunk(error: String) -> Self {
        Self {
            data: format!("[ERROR] {error}").into_bytes(),
            error: Some(error),
        }
    }

    fn error(&self) -> Option<&str> {
        self.error.as_deref()
    }
}

/// Wrapper for String that implements MessageChunk
#[derive(Debug, Clone)]
pub struct StringChunk {
    pub data: String,
    error: Option<String>,
}

impl StringChunk {
    pub fn new(data: String) -> Self {
        Self { data, error: None }
    }

    pub fn into_inner(self) -> String {
        self.data
    }
}

impl MessageChunk for StringChunk {
    fn bad_chunk(error: String) -> Self {
        Self {
            data: format!("[ERROR] {error}"),
            error: Some(error),
        }
    }

    fn error(&self) -> Option<&str> {
        self.error.as_deref()
    }
}
