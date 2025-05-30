//! SHA-256 hash builder

use super::{AsyncHashResult, DataBuilder, HashExecutor, PassesBuilder, SaltBuilder};

/// Initial SHA-256 builder
pub struct Sha256Builder;

/// SHA-256 with data
pub struct Sha256WithData {
    data: Vec<u8>,
}

/// SHA-256 with data and salt
pub struct Sha256WithDataAndSalt {
    data: Vec<u8>,
    salt: Vec<u8>,
}

/// SHA-256 with data and passes
pub struct Sha256WithDataAndPasses {
    data: Vec<u8>,
    passes: u32,
}

/// SHA-256 with all options
pub struct Sha256Complete {
    data: Vec<u8>,
    salt: Vec<u8>,
    passes: u32,
}

// Initial builder
impl DataBuilder for Sha256Builder {
    type Output = Sha256WithData;

    fn with_data<T: Into<Vec<u8>>>(self, data: T) -> Self::Output {
        Sha256WithData { data: data.into() }
    }

    fn with_text<T: Into<String>>(self, text: T) -> Self::Output {
        Sha256WithData {
            data: text.into().into_bytes(),
        }
    }
}

// With data
impl SaltBuilder for Sha256WithData {
    type Output = Sha256WithDataAndSalt;

    fn with_salt<T: Into<Vec<u8>>>(self, salt: T) -> Self::Output {
        Sha256WithDataAndSalt {
            data: self.data,
            salt: salt.into(),
        }
    }
}

impl PassesBuilder for Sha256WithData {
    type Output = Sha256WithDataAndPasses;

    fn with_passes(self, passes: u32) -> Self::Output {
        Sha256WithDataAndPasses {
            data: self.data,
            passes,
        }
    }
}

impl HashExecutor for Sha256WithData {
    fn hash(self) -> impl AsyncHashResult {
        async move {
            use sha2::{Digest, Sha256};

            tokio::task::spawn_blocking(move || {
                let mut hasher = Sha256::new();
                hasher.update(&self.data);
                Ok(hasher.finalize().to_vec())
            })
            .await
            .map_err(|e| crate::CryptError::internal(e.to_string()))?
        }
    }
}

// With data and salt
impl PassesBuilder for Sha256WithDataAndSalt {
    type Output = Sha256Complete;

    fn with_passes(self, passes: u32) -> Self::Output {
        Sha256Complete {
            data: self.data,
            salt: self.salt,
            passes,
        }
    }
}

impl HashExecutor for Sha256WithDataAndSalt {
    fn hash(self) -> impl AsyncHashResult {
        async move {
            use sha2::{Digest, Sha256};

            tokio::task::spawn_blocking(move || {
                let mut input = self.data;
                input.extend_from_slice(&self.salt);

                let mut hasher = Sha256::new();
                hasher.update(&input);
                Ok(hasher.finalize().to_vec())
            })
            .await
            .map_err(|e| crate::CryptError::internal(e.to_string()))?
        }
    }
}

// With data and passes
impl SaltBuilder for Sha256WithDataAndPasses {
    type Output = Sha256Complete;

    fn with_salt<T: Into<Vec<u8>>>(self, salt: T) -> Self::Output {
        Sha256Complete {
            data: self.data,
            salt: salt.into(),
            passes: self.passes,
        }
    }
}

impl HashExecutor for Sha256WithDataAndPasses {
    fn hash(self) -> impl AsyncHashResult {
        async move {
            use sha2::{Digest, Sha256};

            tokio::task::spawn_blocking(move || {
                let mut result = self.data;
                for _ in 0..self.passes {
                    let mut hasher = Sha256::new();
                    hasher.update(&result);
                    result = hasher.finalize().to_vec();
                }
                Ok(result)
            })
            .await
            .map_err(|e| crate::CryptError::internal(e.to_string()))?
        }
    }
}

// Complete builder
impl HashExecutor for Sha256Complete {
    fn hash(self) -> impl AsyncHashResult {
        async move {
            use sha2::{Digest, Sha256};

            tokio::task::spawn_blocking(move || {
                let mut input = self.data;
                input.extend_from_slice(&self.salt);

                let mut result = input;
                for _ in 0..self.passes {
                    let mut hasher = Sha256::new();
                    hasher.update(&result);
                    result = hasher.finalize().to_vec();
                }
                Ok(result)
            })
            .await
            .map_err(|e| crate::CryptError::internal(e.to_string()))?
        }
    }
}
