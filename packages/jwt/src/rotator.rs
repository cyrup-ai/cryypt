//! JWT key rotation support.
//!
//! This module provides thread-safe key rotation for JWT signing operations.
//! It uses lock-free atomic swapping to ensure zero-downtime key rotation.

use crate::{
    error::JwtResult,
    traits::{Header, Signer},
};
use arc_swap::ArcSwap;
use chrono::{DateTime, Utc};
use std::sync::Arc;

/// Thread-safe, immutable key rotation wrapper.
///
/// This allows for seamless key rotation without downtime. The active key
/// can be swapped atomically while requests are in flight.
///
/// # Type Parameters
///
/// * `G` - Generator function that produces new signing keys
/// * `F` - Function that determines when rotation should occur
///
/// # Example
///
/// ```no_run
/// use cryypt::jwt::{Rotator, Hs256Key};
/// use chrono::{Duration, Utc};
///
/// let rotator = Rotator::new(
///     Box::new(Hs256Key::random()),
///     || {
///         // Generate new key with expiry
///         (Box::new(Hs256Key::random()) as Box<dyn Signer>, Utc::now() + Duration::hours(24))
///     },
///     || {
///         // Rotate every hour
///         Utc::now().timestamp() % 3600 == 0
///     },
/// );
/// ```
pub struct Rotator<G, F>
where
    G: Fn() -> (Box<dyn Signer>, DateTime<Utc>) + Send + Sync + 'static,
    F: Fn() -> bool + Send + Sync + 'static,
{
    active: ArcSwap<Box<dyn Signer>>,
    next_key_fn: G,
    rotate_trigger: F,
}

impl<G, F> Rotator<G, F>
where
    G: Fn() -> (Box<dyn Signer>, DateTime<Utc>) + Send + Sync + 'static,
    F: Fn() -> bool + Send + Sync + 'static,
{
    /// Create a new rotator with initial key and rotation logic.
    ///
    /// # Arguments
    ///
    /// * `initial` - The initial signing key to use
    /// * `next_key_fn` - Function that generates the next key and its expiry time
    /// * `rotate_trigger` - Function that returns true when rotation should occur
    pub fn new(initial: Box<dyn Signer>, next_key_fn: G, rotate_trigger: F) -> Self {
        Self {
            active: ArcSwap::from_pointee(initial),
            next_key_fn,
            rotate_trigger,
        }
    }

    /// Check if rotation is needed and perform it if necessary.
    ///
    /// This is called automatically during signing operations.
    fn maybe_rotate(&self) {
        if (self.rotate_trigger)() {
            let (next, _expires) = (self.next_key_fn)();
            self.active.store(Arc::new(next));
        }
    }

    /// Get the current active signer.
    pub fn current(&self) -> Arc<Box<dyn Signer>> {
        self.active.load_full()
    }

    /// Force rotation to occur immediately.
    pub fn force_rotate(&self) {
        let (next, _expires) = (self.next_key_fn)();
        self.active.store(Arc::new(next));
    }
}

impl<G, F> Signer for Rotator<G, F>
where
    G: Fn() -> (Box<dyn Signer>, DateTime<Utc>) + Send + Sync + 'static,
    F: Fn() -> bool + Send + Sync + 'static,
{
    fn sign(&self, header: &Header, payload: &str) -> JwtResult<String> {
        self.maybe_rotate();
        self.active.load().sign(header, payload)
    }

    fn verify(&self, token: &str) -> JwtResult<String> {
        // Note: This only verifies with the current key.
        // In a production system, you might want to keep a list of
        // recent keys for verification to handle in-flight requests.
        self.active.load().verify(token)
    }

    fn alg(&self) -> &'static str {
        self.active.load().alg()
    }

    fn kid(&self) -> Option<String> {
        self.active.load().kid()
    }
}

