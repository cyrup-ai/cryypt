//! JWT token generator with validation support.

use crate::{
    api::claims::Claims,
    error::JwtError,
    futures::{TokenGenerationFuture, TokenVerificationFuture},
    traits::{Header, Signer},
    validation::ValidationOptions,
};
use chrono::Utc;
use std::sync::Arc;
use tokio::sync::oneshot;

/// Core JWT generator.
///
/// This is the main entry point for JWT operations. It wraps a signing
/// algorithm and provides methods for token generation and verification.
pub struct Generator<S: Signer> {
    signer: Arc<S>,
    validation_options: ValidationOptions,
}

impl<S: Signer> Generator<S> {
    /// Create a new generator with the given signer.
    pub fn new(signer: S) -> Self {
        Self {
            signer: Arc::new(signer),
            validation_options: ValidationOptions::default(),
        }
    }

    /// Set custom validation options.
    pub fn with_validation_options(mut self, options: ValidationOptions) -> Self {
        self.validation_options = options;
        self
    }

    /// Get a reference to the validation options.
    pub fn validation_options(&self) -> &ValidationOptions {
        &self.validation_options
    }

    /// Generate a JWT token with the given claims.
    pub fn token(&self, claims: &Claims) -> TokenGenerationFuture {
        let (tx, rx) = oneshot::channel();
        let signer = self.signer.clone();
        let header = Header::new(signer.alg(), signer.kid());
        let claims = claims.clone();

        tokio::spawn(async move {
            // Direct async implementation - JWT signing is fast, no blocking needed
            let result = async move {
                let payload = match serde_json::to_string(&claims) {
                    Ok(p) => p,
                    Err(_) => return Err(JwtError::Malformed),
                };
                signer.sign(&header, &payload)
            }.await;

            let _ = tx.send(result);
        });

        TokenGenerationFuture::new(rx)
    }

    /// Verify a JWT token and extract claims if valid.
    pub fn verify<T: Into<String>>(&self, token: T) -> TokenVerificationFuture {
        let (tx, rx) = oneshot::channel();
        let signer = self.signer.clone();
        let options = self.validation_options.clone();
        let token = token.into();

        tokio::spawn(async move {
            // Direct async implementation - JWT verification and validation are fast, no blocking needed
            let result = async move {
                let payload = signer.verify(&token)?;
                let claims: Claims =
                    serde_json::from_str(&payload).map_err(|_| JwtError::Malformed)?;

                let now = Utc::now().timestamp();
                let leeway = options.leeway.num_seconds();

                // Validate expiry
                if options.validate_exp && claims.exp < now {
                    return Err(JwtError::Expired);
                }

                // Validate not-before
                if options.validate_nbf {
                    if let Some(nbf) = claims.nbf {
                        if nbf > now + leeway {
                            return Err(JwtError::NotYetValid);
                        }
                    }
                }

                // Validate required claims
                for claim in &options.required_claims {
                    if !claims.extra.contains_key(claim) {
                        return Err(JwtError::MissingClaim(claim.clone()));
                    }
                }

                // Validate issuer
                if let Some(expected_iss) = &options.expected_issuer {
                    match &claims.iss {
                        Some(iss) if iss == expected_iss => {}
                        _ => return Err(JwtError::InvalidIssuer),
                    }
                }

                // Validate audience
                if let Some(expected_aud) = &options.expected_audience {
                    match &claims.aud {
                        Some(aud) => {
                            let valid = expected_aud.iter().any(|e| aud.contains(e));
                            if !valid {
                                return Err(JwtError::InvalidAudience);
                            }
                        }
                        None => return Err(JwtError::InvalidAudience),
                    }
                }

                Ok(claims)
            }.await;

            let _ = tx.send(result);
        });

        TokenVerificationFuture::new(rx)
    }
}

impl<S: Signer> Clone for Generator<S> {
    fn clone(&self) -> Self {
        Self {
            signer: self.signer.clone(),
            validation_options: self.validation_options.clone(),
        }
    }
}

