//! Traits for the hashing builder pattern

use super::passes::HashPasses;
use crate::Result;
use std::future::Future;

/// Async result for hash operations
pub trait AsyncHashResult: Future<Output = Result<Vec<u8>>> + Send {}
impl<T> AsyncHashResult for T where T: Future<Output = Result<Vec<u8>>> + Send {}

/// Trait for setting data to hash
pub trait DataBuilder {
    /// The resulting type after adding data
    type Output;

    /// Set the data to hash (as bytes)
    fn with_data<T: Into<Vec<u8>>>(self, data: T) -> Self::Output;

    /// Set the data to hash (as text)
    fn with_text<T: Into<String>>(self, text: T) -> Self::Output;
}

/// Trait for setting salt
pub trait SaltBuilder {
    /// The resulting type after adding salt
    type Output;

    /// Set the salt for hashing
    fn with_salt<T: Into<Vec<u8>>>(self, salt: T) -> Self::Output;
}

/// Trait for setting number of passes
pub trait PassesBuilder {
    /// The resulting type after adding passes configuration
    type Output;

    /// Set the number of passes for iterative hashing
    fn with_passes(self, passes: HashPasses) -> Self::Output;
}

/// Trait for executing the hash operation
pub trait HashExecutor {
    /// Execute the hash operation
    fn hash(self) -> impl AsyncHashResult;
}
