//! Builder traits module for post-quantum cryptography operations
//!
//! Contains trait definitions for type-safe builder patterns across PQ crypto operations.

use crate::Result;
use std::future::Future;

// Declare submodules
pub mod execution;
pub mod keypair;
pub mod operations;

// Re-export all traits from submodules for external use
pub use execution::*;
pub use keypair::*;
pub use operations::*;

/// Async result type for encapsulation operations
pub trait AsyncEncapsulationResult:
    Future<Output = Result<super::super::EncapsulationResult>> + Send
{
}

impl<T> AsyncEncapsulationResult for T where
    T: Future<Output = Result<super::super::EncapsulationResult>> + Send
{
}

/// Async result type for decapsulation operations
pub trait AsyncDecapsulationResult:
    Future<Output = Result<super::super::DecapsulationResult>> + Send
{
}

impl<T> AsyncDecapsulationResult for T where
    T: Future<Output = Result<super::super::DecapsulationResult>> + Send
{
}

/// Async result type for signature operations
pub trait AsyncSignatureResult:
    Future<Output = Result<super::super::SignatureResult>> + Send
{
}

impl<T> AsyncSignatureResult for T where
    T: Future<Output = Result<super::super::SignatureResult>> + Send
{
}

/// Async result type for verification operations
pub trait AsyncVerificationResult:
    Future<Output = Result<super::super::VerificationResult>> + Send
{
}

impl<T> AsyncVerificationResult for T where
    T: Future<Output = Result<super::super::VerificationResult>> + Send
{
}
