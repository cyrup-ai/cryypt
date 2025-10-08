//! Algorithm-specific JWT builders following polymorphic pattern
//!
//! This module provides algorithm-specific builders that integrate with the existing
//! JWT system while following the polymorphic pattern from cipher module.

pub mod hs256_builder;
pub mod rs256_builder;

pub use hs256_builder::{
    HsJwtBuilder, HsJwtWithSecret, HsJwtWithSecretAndClaims,
    HsJwtWithSecretAndClaimsAndChunkHandler, HsJwtWithSecretAndClaimsAndHandler,
};
pub use rs256_builder::{
    RsJwtBuilder, RsJwtWithPrivateKey, RsJwtWithPrivateKeyAndClaims,
    RsJwtWithPrivateKeyAndClaimsAndChunkHandler, RsJwtWithPrivateKeyAndClaimsAndHandler,
};
