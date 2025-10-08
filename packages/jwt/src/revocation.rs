//! JWT token revocation with automatic cleanup.
//!
//! This module provides in-memory token revocation with automatic cleanup
//! of expired tokens to prevent memory leaks.

use crate::{
    api::claims::Claims,
    error::{JwtError, JwtResult},
    futures::{CleanupStartFuture, TokenGenerationFuture, TokenVerificationFuture},
    generator::Generator,
    traits::Signer,
};
use chrono::{DateTime, Duration, Utc};
use dashmap::DashMap;
use once_cell::sync::Lazy;
use std::future::Future;
use std::hash::BuildHasherDefault;
use std::sync::Arc;
use tokio::sync::{oneshot, RwLock};
use twox_hash::XxHash64;

/// Hash builder for efficient token hashing.
static HASHER: Lazy<BuildHasherDefault<XxHash64>> = Lazy::new(BuildHasherDefault::default);

/// Information about a revoked token.
#[derive(Debug, Clone)]
pub struct RevokedToken {
    /// Token hash.
    pub hash: u64,
    /// Reason for revocation.
    pub reason: String,
    /// When the token was revoked.
    pub revoked_at: DateTime<Utc>,
    /// When the token expires (for cleanup).
    pub expires_at: DateTime<Utc>,
}

/// In-memory revocation store with automatic cleanup.
///
/// This provides a way to revoke JWT tokens before their natural expiry.
/// Revoked tokens are stored by hash to save memory, and expired tokens
/// are automatically cleaned up to prevent unbounded memory growth.
///
/// # Example
///
/// ```no_run
/// use cryypt::jwt::{Revocation, Hs256Key};
/// use chrono::Duration;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let key = Hs256Key::random();
/// let revocation = Revocation::wrap(key);
///
/// // Start automatic cleanup every 5 minutes
/// revocation.start_cleanup(Duration::minutes(5)).await;
///
/// // Generate a token
/// let claims = // ... create claims
/// # cryypt::jwt::ClaimsBuilder::new()
/// #     .subject("user")
/// #     .expires_in(Duration::hours(1))
/// #     .issued_now()
/// #     .build();
/// let token = revocation.token(&claims).await?;
///
/// // Revoke the token
/// revocation.revoke(&token, "User logged out");
///
/// // Token is now rejected
/// let result = revocation.verify(&token).await;
/// assert!(result.is_err());
/// # Ok(())
/// # }
/// ```
pub struct Revocation<S: Signer> {
    inner: Arc<S>,
    revoked: Arc<DashMap<u64, RevokedToken, BuildHasherDefault<XxHash64>>>,
    cleanup_task: Arc<RwLock<Option<tokio::task::JoinHandle<()>>>>,
}

impl<S: Signer> Revocation<S> {
    /// Wrap a signer with revocation support.
    pub fn wrap(inner: S) -> Self {
        let revoked = Arc::new(DashMap::with_hasher(HASHER.clone()));
        let cleanup_task = Arc::new(RwLock::new(None));

        Self {
            inner: Arc::new(inner),
            revoked,
            cleanup_task,
        }
    }

    /// Start automatic cleanup task.
    ///
    /// This spawns a background task that periodically removes expired tokens
    /// from the revocation store. Only one cleanup task can run at a time;
    /// calling this again will stop the previous task.
    ///
    /// # Arguments
    ///
    /// * `interval` - How often to run cleanup
    pub fn start_cleanup(&self, interval: Duration) -> CleanupStartFuture {
        let (tx, rx) = oneshot::channel();
        let revoked = self.revoked.clone();
        let cleanup_task = self.cleanup_task.clone();

        tokio::spawn(async move {
            let handle = tokio::spawn(async move {
                let std_duration = match interval.to_std() {
                    Ok(duration) => duration,
                    Err(_) => return, // Invalid duration, exit cleanup task
                };
                let mut interval = tokio::time::interval(std_duration);
                loop {
                    interval.tick().await;
                    let now = Utc::now();
                    revoked.retain(|_, token| token.expires_at > now);
                }
            });

            *cleanup_task.write().await = Some(handle);
            let _ = tx.send(());
        });

        CleanupStartFuture::new(rx)
    }

    /// Stop cleanup task.
    pub fn stop_cleanup(&self) -> impl Future<Output = ()> + '_ {
        async move {
            if let Some(handle) = self.cleanup_task.write().await.take() {
                handle.abort();
            }
        }
    }

    /// Revoke a token with the given reason.
    ///
    /// The token will be rejected by `verify()` until it naturally expires.
    /// Invalid tokens can be safely revoked without error.
    ///
    /// # Arguments
    ///
    /// * `token` - The JWT token to revoke
    /// * `reason` - Human-readable reason for revocation
    pub fn revoke(&self, token: &str, reason: impl Into<String>) {
        // Parse token to get expiry
        let exp = match self.extract_expiry(token) {
            Ok(exp) => exp,
            Err(_) => Utc::now() + Duration::days(30), // Default 30 days
        };

        let revoked_token = RevokedToken {
            hash: Self::hash(token),
            reason: reason.into(),
            revoked_at: Utc::now(),
            expires_at: exp,
        };

        self.revoked.insert(revoked_token.hash, revoked_token);
    }

    /// Extract expiry from a token without full verification.
    ///
    /// This is used internally to determine when to clean up revoked tokens.
    fn extract_expiry(&self, token: &str) -> JwtResult<DateTime<Utc>> {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return Err(JwtError::Malformed);
        }

        let payload_bytes = base64_url::decode(parts[1]).map_err(|_| JwtError::Malformed)?;
        let payload = String::from_utf8(payload_bytes).map_err(|_| JwtError::Malformed)?;
        let claims: Claims = serde_json::from_str(&payload).map_err(|_| JwtError::Malformed)?;

        DateTime::from_timestamp(claims.exp, 0)
            .ok_or(JwtError::Malformed)
            .map(Ok)?
    }

    /// Generate a JWT token with the given claims using the wrapped signer.
    pub fn token(&self, claims: &Claims) -> TokenGenerationFuture {
        Generator::new(self.inner.clone()).token(claims)
    }

    /// Verify a JWT token and extract claims if valid and not revoked.
    pub fn verify<T: Into<String>>(&self, token: T) -> TokenVerificationFuture {
        let (tx, rx) = oneshot::channel();
        let token_str = token.into();
        let hash = Self::hash(&token_str);
        let revoked = self.revoked.clone();
        let inner = self.inner.clone();

        tokio::spawn(async move {
            if revoked.contains_key(&hash) {
                let _ = tx.send(Err(JwtError::Revoked));
                return;
            }

            let generator = Generator::new(inner);

            // Await the verification future
            let result = generator.verify(token_str).await;

            let _ = tx.send(result);
        });

        TokenVerificationFuture::new(rx)
    }

    /// Manually cleanup expired tokens.
    ///
    /// This can be called in addition to or instead of automatic cleanup.
    pub fn cleanup_expired(&self) {
        let now = Utc::now();
        self.revoked.retain(|_, token| token.expires_at > now);
    }

    /// Hash a token for storage.
    ///
    /// We store hashes instead of full tokens to save memory.
    fn hash(t: &str) -> u64 {
        use std::hash::{BuildHasher, Hasher};
        let mut h = (*HASHER).build_hasher();
        h.write(t.as_bytes());
        h.finish()
    }

    /// Get the number of revoked tokens currently stored.
    pub fn revoked_count(&self) -> usize {
        self.revoked.len()
    }

    /// Check if a specific token is revoked without verifying it.
    pub fn is_revoked(&self, token: &str) -> bool {
        self.revoked.contains_key(&Self::hash(token))
    }

    /// Get information about a revoked token if it exists.
    pub fn get_revocation_info(&self, token: &str) -> Option<RevokedToken> {
        self.revoked.get(&Self::hash(token)).map(|r| r.clone())
    }
}

impl<S: Signer> Drop for Revocation<S> {
    fn drop(&mut self) {
        // Stop cleanup task if running
        if let Ok(mut guard) = self.cleanup_task.try_write() {
            if let Some(handle) = guard.take() {
                handle.abort();
            }
        }
    }
}

