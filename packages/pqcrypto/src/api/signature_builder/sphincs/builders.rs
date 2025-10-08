//! SPHINCS+ message and signature builders

use super::super::super::{
    builder_traits::{MessageBuilder, SignatureDataBuilder},
    states::{HasMessage, HasSignature},
};
use super::core::SphincsBuilder;
use std::marker::PhantomData;

// Message builder implementations for SPHINCS+
impl<State> MessageBuilder for SphincsBuilder<State> {
    type Output = SphincsBuilder<HasMessage>;

    fn with_message<T: Into<Vec<u8>>>(self, message: T) -> Self::Output {
        SphincsBuilder {
            algorithm: self.algorithm,
            state: PhantomData,
            public_key: self.public_key,
            secret_key: self.secret_key,
            message: Some(message.into()),
            signature: self.signature,
        }
    }
}

// Signature data builder implementations for SPHINCS+
impl<State> SignatureDataBuilder for SphincsBuilder<State> {
    type Output = SphincsBuilder<HasSignature>;

    fn with_signature<T: Into<Vec<u8>>>(self, signature: T) -> Self::Output {
        SphincsBuilder {
            algorithm: self.algorithm,
            state: PhantomData,
            public_key: self.public_key,
            secret_key: self.secret_key,
            message: self.message,
            signature: Some(signature.into()),
        }
    }
}
