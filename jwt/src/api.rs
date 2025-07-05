//! JWT API following README.md patterns

pub mod hs256_builder;
pub mod es256_builder;
pub mod rotator_builder;

use crate::{error::*, types::*};

/// Master builder for JWT operations - README.md pattern
pub struct JwtMasterBuilder;

impl JwtMasterBuilder {
    /// Start building HS256 JWT - README.md pattern
    pub fn hs256(self) -> hs256_builder::Hs256Builder {
        hs256_builder::Hs256Builder::new()
    }
    
    /// Start building ES256 JWT - README.md pattern  
    pub fn es256(self) -> es256_builder::Es256Builder {
        es256_builder::Es256Builder::new()
    }
    
    /// Start building JWT rotator - README.md pattern
    pub fn rotator(self) -> rotator_builder::RotatorBuilder {
        rotator_builder::RotatorBuilder::new()
    }
}

/// Direct builder entry point - equivalent to Cryypt::jwt()
pub struct Jwt;

impl Jwt {
    /// Start building HS256 JWT - README.md pattern
    pub fn hs256() -> hs256_builder::Hs256Builder {
        hs256_builder::Hs256Builder::new()
    }
    
    /// Start building ES256 JWT - README.md pattern
    pub fn es256() -> es256_builder::Es256Builder {
        es256_builder::Es256Builder::new()
    }
    
    /// Start building JWT rotator - README.md pattern
    pub fn rotator() -> rotator_builder::RotatorBuilder {
        rotator_builder::RotatorBuilder::new()
    }
}

/// Macro to handle results - hidden from users per README.md
#[macro_export]
macro_rules! on_result {
    ($handler:expr) => {
        $handler
    };
}