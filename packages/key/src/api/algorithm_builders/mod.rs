//! Algorithm-specific key builders following polymorphic pattern
//!
//! This module provides algorithm-specific builders that integrate with the existing
//! `KeyGenerator` system while following the polymorphic pattern from cipher module.

pub mod aes_builder;
pub mod rsa_builder;

pub use aes_builder::{
    AesKeyBuilder, AesKeyWithSize, AesKeyWithSizeAndChunkHandler, AesKeyWithSizeAndHandler,
};
pub use rsa_builder::{
    RsaKeyBuilder, RsaKeyWithSize, RsaKeyWithSizeAndChunkHandler, RsaKeyWithSizeAndHandler,
};
