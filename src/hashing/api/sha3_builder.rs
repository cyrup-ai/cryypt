//! SHA3-256 hash builder

use super::{AsyncHashResult, DataBuilder, HashExecutor, PassesBuilder, SaltBuilder, HashPasses};

/// Initial SHA3 builder
pub struct Sha3Builder;

/// SHA3 with data
pub struct Sha3WithData {
    data: Vec<u8>,
}

/// SHA3 with data and salt
pub struct Sha3WithDataAndSalt {
    data: Vec<u8>,
    salt: Vec<u8>,
}

/// SHA3 with data and passes
pub struct Sha3WithDataAndPasses {
    data: Vec<u8>,
    passes: u32,
}

/// SHA3 with all options
pub struct Sha3Complete {
    data: Vec<u8>,
    salt: Vec<u8>,
    passes: u32,
}

// Initial builder
impl DataBuilder for Sha3Builder {
    type Output = Sha3WithData;

    fn with_data<T: Into<Vec<u8>>>(self, data: T) -> Self::Output {
        Sha3WithData { data: data.into() }
    }

    fn with_text<T: Into<String>>(self, text: T) -> Self::Output {
        Sha3WithData {
            data: text.into().into_bytes(),
        }
    }
}

// With data
impl SaltBuilder for Sha3WithData {
    type Output = Sha3WithDataAndSalt;

    fn with_salt<T: Into<Vec<u8>>>(self, salt: T) -> Self::Output {
        Sha3WithDataAndSalt {
            data: self.data,
            salt: salt.into(),
        }
    }
}

impl PassesBuilder for Sha3WithData {
    type Output = Sha3WithDataAndPasses;

    fn with_passes(self, passes: HashPasses) -> Self::Output {
        Sha3WithDataAndPasses {
            data: self.data,
            passes: passes.iterations(),
        }
    }
}

impl HashExecutor for Sha3WithData {
    fn hash(self) -> impl AsyncHashResult {
        async move {
            use sha3::{Digest, Sha3_256};

            tokio::task::spawn_blocking(move || {
                let mut hasher = Sha3_256::new();
                hasher.update(&self.data);
                Ok(hasher.finalize().to_vec())
            })
            .await
            .map_err(|e| crate::CryptError::internal(e.to_string()))?
        }
    }
}

// With data and salt
impl PassesBuilder for Sha3WithDataAndSalt {
    type Output = Sha3Complete;

    fn with_passes(self, passes: HashPasses) -> Self::Output {
        Sha3Complete {
            data: self.data,
            salt: self.salt,
            passes: passes.iterations(),
        }
    }
}

impl HashExecutor for Sha3WithDataAndSalt {
    fn hash(self) -> impl AsyncHashResult {
        async move {
            use sha3::{Digest, Sha3_256};

            tokio::task::spawn_blocking(move || {
                let mut input = self.data;
                input.extend_from_slice(&self.salt);

                let mut hasher = Sha3_256::new();
                hasher.update(&input);
                Ok(hasher.finalize().to_vec())
            })
            .await
            .map_err(|e| crate::CryptError::internal(e.to_string()))?
        }
    }
}

// With data and passes
impl SaltBuilder for Sha3WithDataAndPasses {
    type Output = Sha3Complete;

    fn with_salt<T: Into<Vec<u8>>>(self, salt: T) -> Self::Output {
        Sha3Complete {
            data: self.data,
            salt: salt.into(),
            passes: self.passes,
        }
    }
}

impl HashExecutor for Sha3WithDataAndPasses {
    fn hash(self) -> impl AsyncHashResult {
        async move {
            use sha3::{Digest, Sha3_256};

            tokio::task::spawn_blocking(move || {
                let mut result = self.data;
                for _ in 0..self.passes {
                    let mut hasher = Sha3_256::new();
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
impl HashExecutor for Sha3Complete {
    fn hash(self) -> impl AsyncHashResult {
        async move {
            use sha3::{Digest, Sha3_256};

            tokio::task::spawn_blocking(move || {
                let mut input = self.data;
                input.extend_from_slice(&self.salt);

                let mut result = input;
                for _ in 0..self.passes {
                    let mut hasher = Sha3_256::new();
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
