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
    
    /// Validate JWT claims for consistency
    pub fn validate_claims(claims: &JwtClaims) -> Result<(), JwtError> {
        if claims.exp.is_some() && claims.nbf.is_some() {
            if let (Some(exp), Some(nbf)) = (claims.exp, claims.nbf) {
                if exp <= nbf {
                    return Err(JwtError::invalid_claims("Expiration time must be after not-before time"));
                }
            }
        }
        Ok(())
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

/// Internal macro - NOT PUBLIC API
macro_rules! on_result {
    ($handler:expr) => {
        $handler
    };
}