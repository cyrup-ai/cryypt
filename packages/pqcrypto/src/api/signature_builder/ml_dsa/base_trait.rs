//! Base trait implementation for ML-DSA signature builder

use super::super::common::BaseSignatureBuilder;
use super::types::MlDsaBuilder;
use crate::algorithm::SignatureAlgorithm;

impl<State> BaseSignatureBuilder for MlDsaBuilder<State> {
    fn algorithm(&self) -> SignatureAlgorithm {
        self.algorithm
    }
}
