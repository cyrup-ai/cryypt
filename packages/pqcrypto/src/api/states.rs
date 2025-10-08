//! State types for builder patterns in post-quantum cryptography

use std::marker::PhantomData;

/// Marker trait for builder states
#[allow(dead_code)]
pub trait BuilderState: Send + Sync + 'static {}

// KEM States

/// State indicating that a key pair is needed
#[derive(Debug, Clone, Copy)]
pub struct NeedKeyPair;
impl BuilderState for NeedKeyPair {}

/// State indicating that a key pair has been provided
#[derive(Debug, Clone, Copy)]
pub struct HasKeyPair;
impl BuilderState for HasKeyPair {}

/// State indicating that only a public key has been provided
#[derive(Debug, Clone, Copy)]
pub struct HasPublicKey;
impl BuilderState for HasPublicKey {}

/// State indicating that only a secret key has been provided
#[derive(Debug, Clone, Copy)]
pub struct HasSecretKey;
impl BuilderState for HasSecretKey {}

/// State indicating that ciphertext is needed
#[derive(Debug, Clone, Copy)]
pub struct NeedCiphertext;
impl BuilderState for NeedCiphertext {}

/// State indicating that ciphertext has been provided
#[derive(Debug, Clone, Copy)]
pub struct HasCiphertext;
impl BuilderState for HasCiphertext {}

// Signature States

/// State indicating that a message is needed
#[derive(Debug, Clone, Copy)]
pub struct NeedMessage;
impl BuilderState for NeedMessage {}

/// State indicating that a message has been provided
#[derive(Debug, Clone, Copy)]
pub struct HasMessage;
impl BuilderState for HasMessage {}

/// State indicating that a signature is needed
#[derive(Debug, Clone, Copy)]
pub struct NeedSignature;
impl BuilderState for NeedSignature {}

/// State indicating that a signature has been provided
#[derive(Debug, Clone, Copy)]
pub struct HasSignature;
impl BuilderState for HasSignature {}

/// Phantom type helper for state tracking
#[allow(dead_code)]
pub struct StateMarker<T: BuilderState> {
    _phantom: PhantomData<T>,
}

impl<T: BuilderState> StateMarker<T> {
    #[allow(dead_code)]
    pub fn new() -> Self {
        Self {
            _phantom: PhantomData,
        }
    }
}

impl<T: BuilderState> Default for StateMarker<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: BuilderState> Clone for StateMarker<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T: BuilderState> Copy for StateMarker<T> {}
