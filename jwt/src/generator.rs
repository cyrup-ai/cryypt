//! JWT token generator with validation support.

use crate::{
    claims::Claims,
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
            let result = tokio::task::spawn_blocking(move || {
                let payload = match serde_json::to_string(&claims) {
                    Ok(p) => p,
                    Err(_) => return Err(JwtError::Malformed),
                };
                signer.sign(&header, &payload)
            })
            .await
            .unwrap_or_else(|_| Err(JwtError::TaskJoinError));

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
            let result = tokio::task::spawn_blocking(move || {
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
            })
            .await
            .unwrap_or_else(|_| Err(JwtError::TaskJoinError));

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{algorithms::Hs256Key, claims::ClaimsBuilder};
    use chrono::Duration;

    #[tokio::test]
    async fn test_generator_token_generation() {
        let key = Hs256Key::random();
        let generator = Generator::new(key);

        let claims = ClaimsBuilder::new()
            .subject("test-user")
            .expires_in(Duration::hours(1))
            .issued_now()
            .build();

        let token = generator.token(&claims).await.unwrap();
        assert!(!token.is_empty());
        assert_eq!(token.matches('.').count(), 2);
    }

    #[tokio::test]
    async fn test_generator_token_verification() {
        let key = Hs256Key::random();
        let generator = Generator::new(key);

        let claims = ClaimsBuilder::new()
            .subject("test-user")
            .expires_in(Duration::hours(1))
            .issued_now()
            .issuer("test-issuer")
            .build();

        let token = generator.token(&claims).await.unwrap();
        let verified = generator.verify(&token).await.unwrap();

        assert_eq!(verified.sub, "test-user");
        assert_eq!(verified.iss, Some("test-issuer".to_string()));
    }

    #[tokio::test]
    async fn test_generator_with_validation_options() {
        let key = Hs256Key::random();
        let validation_opts = ValidationOptions {
            required_claims: vec!["role".to_string()],
            expected_issuer: Some("expected-issuer".to_string()),
            ..Default::default()
        };

        let generator = Generator::new(key).with_validation_options(validation_opts);

        // Token without required claim should fail
        let claims = ClaimsBuilder::new()
            .subject("test-user")
            .expires_in(Duration::hours(1))
            .issued_now()
            .issuer("expected-issuer")
            .build();

        let token = generator.token(&claims).await.unwrap();
        let result = generator.verify(&token).await;
        assert!(matches!(result, Err(JwtError::MissingClaim(_))));

        // Token with wrong issuer should fail
        let claims_wrong_issuer = ClaimsBuilder::new()
            .subject("test-user")
            .expires_in(Duration::hours(1))
            .issued_now()
            .issuer("wrong-issuer")
            .claim("role".to_string(), serde_json::json!("admin"))
            .build();

        let token = generator.token(&claims_wrong_issuer).await.unwrap();
        let result = generator.verify(&token).await;
        assert!(matches!(result, Err(JwtError::InvalidIssuer)));
    }

    #[tokio::test]
    async fn test_generator_expired_token() {
        let key = Hs256Key::random();
        let generator = Generator::new(key);

        let claims = ClaimsBuilder::new()
            .subject("test-user")
            .expires_in(Duration::seconds(-10)) // Already expired
            .issued_now()
            .build();

        let token = generator.token(&claims).await.unwrap();
        let result = generator.verify(&token).await;
        assert!(matches!(result, Err(JwtError::Expired)));
    }
}
