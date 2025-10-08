//! Core SPHINCS+ builder struct and base implementation

use super::super::super::super::SignatureAlgorithm;
use std::marker::PhantomData;

/// SPHINCS+ builder type
pub struct SphincsBuilder<State> {
    pub(crate) algorithm: SignatureAlgorithm,
    pub(crate) state: PhantomData<State>,
    pub(crate) public_key: Option<Vec<u8>>,
    pub(crate) secret_key: Option<Vec<u8>>,
    pub(crate) message: Option<Vec<u8>>,
    pub(crate) signature: Option<Vec<u8>>,
}

impl<State> SphincsBuilder<State> {
    /// Get the algorithm used by this builder
    #[must_use]
    pub fn algorithm(&self) -> SignatureAlgorithm {
        self.algorithm
    }
}
