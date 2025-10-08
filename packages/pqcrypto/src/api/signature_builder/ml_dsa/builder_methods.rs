//! ML-DSA builder pattern methods for message and signature data

use super::super::super::{
    builder_traits::{MessageBuilder, SignatureDataBuilder},
    states::{HasMessage, HasSignature},
};
use super::types::MlDsaBuilder;
use std::marker::PhantomData;

// Message builder implementations for ML-DSA
impl<State> MessageBuilder for MlDsaBuilder<State> {
    type Output = MlDsaBuilder<HasMessage>;

    fn with_message<T: Into<Vec<u8>>>(self, message: T) -> Self::Output {
        MlDsaBuilder {
            algorithm: self.algorithm,
            state: PhantomData,
            public_key: self.public_key,
            secret_key: self.secret_key,
            message: Some(message.into()),
            signature: self.signature,
        }
    }
}

// Signature data builder implementations for ML-DSA
impl<State> SignatureDataBuilder for MlDsaBuilder<State> {
    type Output = MlDsaBuilder<HasSignature>;

    fn with_signature<T: Into<Vec<u8>>>(self, signature: T) -> Self::Output {
        MlDsaBuilder {
            algorithm: self.algorithm,
            state: PhantomData,
            public_key: self.public_key,
            secret_key: self.secret_key,
            message: self.message,
            signature: Some(signature.into()),
        }
    }
}
