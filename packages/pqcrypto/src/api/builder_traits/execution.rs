//! Final execution builder traits
//!
//! Contains traits for executing cryptographic operations (encapsulate, decapsulate, sign, verify).

use super::{
    AsyncDecapsulationResult, AsyncEncapsulationResult, AsyncSignatureResult,
    AsyncVerificationResult,
};

/// Final stage builder that can encapsulate
pub trait EncapsulateBuilder {
    /// Perform key encapsulation operation
    fn encapsulate(self) -> impl AsyncEncapsulationResult;
}

/// Final stage builder that can decapsulate
pub trait DecapsulateBuilder {
    /// Perform key decapsulation operation
    fn decapsulate(self) -> impl AsyncDecapsulationResult;
}

/// Final stage builder that can sign
pub trait SignBuilder {
    /// Perform digital signature operation
    fn sign(self) -> impl AsyncSignatureResult;
}

/// Final stage builder that can verify
pub trait VerifyBuilder {
    /// Perform signature verification operation
    fn verify(self) -> impl AsyncVerificationResult;
}
