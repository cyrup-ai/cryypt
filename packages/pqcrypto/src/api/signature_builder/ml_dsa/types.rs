//! ML-DSA type definitions and aliases

use super::super::super::states::{
    HasKeyPair, HasMessage, HasPublicKey, HasSecretKey, HasSignature,
};
use crate::algorithm::SignatureAlgorithm;
use std::marker::PhantomData;

/// ML-DSA builder type
pub struct MlDsaBuilder<State> {
    pub(crate) algorithm: SignatureAlgorithm,
    pub(crate) state: PhantomData<State>,
    pub(crate) public_key: Option<Vec<u8>>,
    pub(crate) secret_key: Option<Vec<u8>>,
    pub(crate) message: Option<Vec<u8>>,
    pub(crate) signature: Option<Vec<u8>>,
}

/// ML-DSA builder with a complete key pair (public and secret keys)
pub type MlDsaWithKeyPair = MlDsaBuilder<HasKeyPair>;
/// ML-DSA builder with only the secret key for signing
pub type MlDsaWithSecretKey = MlDsaBuilder<HasSecretKey>;
/// ML-DSA builder with only the public key for verification
pub type MlDsaWithPublicKey = MlDsaBuilder<HasPublicKey>;
/// ML-DSA builder with message ready for signing
pub type MlDsaWithMessage = MlDsaBuilder<HasMessage>;
/// ML-DSA builder with signature ready for verification
pub type MlDsaWithSignature = MlDsaBuilder<HasSignature>;
