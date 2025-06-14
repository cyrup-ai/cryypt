//! Blake2b hash builder

use super::{AsyncHashResult, DataBuilder, HashExecutor, HashPasses, PassesBuilder, SaltBuilder};

/// Initial Blake2b builder
pub struct Blake2bBuilder;

/// Blake2b with data
pub struct Blake2bWithData {
    data: Vec<u8>,
}

/// Blake2b with data and salt
pub struct Blake2bWithDataAndSalt {
    data: Vec<u8>,
    salt: Vec<u8>,
}

/// Blake2b with data and passes
pub struct Blake2bWithDataAndPasses {
    data: Vec<u8>,
    passes: u32,
}

/// Blake2b with all options
pub struct Blake2bComplete {
    data: Vec<u8>,
    salt: Vec<u8>,
    passes: u32,
}

// Initial builder
impl DataBuilder for Blake2bBuilder {
    type Output = Blake2bWithData;

    fn with_data<T: Into<Vec<u8>>>(self, data: T) -> Self::Output {
        Blake2bWithData { data: data.into() }
    }

    fn with_text<T: Into<String>>(self, text: T) -> Self::Output {
        Blake2bWithData {
            data: text.into().into_bytes(),
        }
    }
}

// With data
impl SaltBuilder for Blake2bWithData {
    type Output = Blake2bWithDataAndSalt;

    fn with_salt<T: Into<Vec<u8>>>(self, salt: T) -> Self::Output {
        Blake2bWithDataAndSalt {
            data: self.data,
            salt: salt.into(),
        }
    }
}

impl PassesBuilder for Blake2bWithData {
    type Output = Blake2bWithDataAndPasses;

    fn with_passes(self, passes: HashPasses) -> Self::Output {
        Blake2bWithDataAndPasses {
            data: self.data,
            passes: passes.iterations(),
        }
    }
}

impl HashExecutor for Blake2bWithData {
    fn hash(self) -> impl AsyncHashResult {
        async move {
            use blake2::{Blake2b512, Digest};

            tokio::task::spawn_blocking(move || {
                let mut hasher = Blake2b512::new();
                hasher.update(&self.data);
                Ok(hasher.finalize().to_vec())
            })
            .await
            .map_err(|e| crate::HashError::internal(e.to_string()))?
        }
    }
}

// With data and salt
impl PassesBuilder for Blake2bWithDataAndSalt {
    type Output = Blake2bComplete;

    fn with_passes(self, passes: HashPasses) -> Self::Output {
        Blake2bComplete {
            data: self.data,
            salt: self.salt,
            passes: passes.iterations(),
        }
    }
}

impl HashExecutor for Blake2bWithDataAndSalt {
    fn hash(self) -> impl AsyncHashResult {
        async move {
            use blake2::{Blake2b512, Digest};

            tokio::task::spawn_blocking(move || {
                let mut input = self.data;
                input.extend_from_slice(&self.salt);

                let mut hasher = Blake2b512::new();
                hasher.update(&input);
                Ok(hasher.finalize().to_vec())
            })
            .await
            .map_err(|e| crate::HashError::internal(e.to_string()))?
        }
    }
}

// With data and passes
impl SaltBuilder for Blake2bWithDataAndPasses {
    type Output = Blake2bComplete;

    fn with_salt<T: Into<Vec<u8>>>(self, salt: T) -> Self::Output {
        Blake2bComplete {
            data: self.data,
            salt: salt.into(),
            passes: self.passes,
        }
    }
}

impl HashExecutor for Blake2bWithDataAndPasses {
    fn hash(self) -> impl AsyncHashResult {
        async move {
            use blake2::{Blake2b512, Digest};

            tokio::task::spawn_blocking(move || {
                let mut result = self.data;
                for _ in 0..self.passes {
                    let mut hasher = Blake2b512::new();
                    hasher.update(&result);
                    result = hasher.finalize().to_vec();
                }
                Ok(result)
            })
            .await
            .map_err(|e| crate::HashError::internal(e.to_string()))?
        }
    }
}

// Complete builder
impl HashExecutor for Blake2bComplete {
    fn hash(self) -> impl AsyncHashResult {
        async move {
            use blake2::{Blake2b512, Digest};

            tokio::task::spawn_blocking(move || {
                let mut input = self.data;
                input.extend_from_slice(&self.salt);

                let mut result = input;
                for _ in 0..self.passes {
                    let mut hasher = Blake2b512::new();
                    hasher.update(&result);
                    result = hasher.finalize().to_vec();
                }
                Ok(result)
            })
            .await
            .map_err(|e| crate::HashError::internal(e.to_string()))?
        }
    }
}
