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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        algorithms::Hs256Key,
        claims::{Claims, ClaimsBuilder},
    };
    use chrono::Duration;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Arc;

    #[test]
    fn test_rotator_creation() {
        let rotator = Rotator::new(
            Box::new(Hs256Key::random()),
            || {
                (
                    Box::new(Hs256Key::random()) as Box<dyn Signer>,
                    Utc::now() + Duration::hours(1),
                )
            },
            || false, // Never rotate
        );

        assert_eq!(rotator.alg(), "HS256");
    }

    #[tokio::test]
    async fn test_rotator_rotation() {
        let rotation_count = Arc::new(AtomicUsize::new(0));
        let should_rotate = Arc::new(AtomicBool::new(false));

        let rotation_count_clone = rotation_count.clone();
        let should_rotate_clone = should_rotate.clone();

        let rotator = Rotator::new(
            Box::new(Hs256Key::random()),
            move || {
                rotation_count_clone.fetch_add(1, Ordering::SeqCst);
                (
                    Box::new(Hs256Key::random()) as Box<dyn Signer>,
                    Utc::now() + Duration::hours(1),
                )
            },
            move || should_rotate_clone.load(Ordering::SeqCst),
        );

        let header = Header::new("HS256", None);
        let payload = r#"{"sub":"test"}"#;

        // Sign before rotation
        let _token1 = rotator.sign(&header, payload).unwrap();
        assert_eq!(rotation_count.load(Ordering::SeqCst), 0);

        // Trigger rotation
        should_rotate.store(true, Ordering::SeqCst);
        let _token2 = rotator.sign(&header, payload).unwrap();
        assert_eq!(rotation_count.load(Ordering::SeqCst), 1);

        // Sign again (should not rotate again)
        should_rotate.store(false, Ordering::SeqCst);
        let _token3 = rotator.sign(&header, payload).unwrap();
        assert_eq!(rotation_count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn test_rotator_force_rotate() {
        let rotation_count = Arc::new(AtomicUsize::new(0));
        let rotation_count_clone = rotation_count.clone();

        let rotator = Rotator::new(
            Box::new(Hs256Key::random()),
            move || {
                rotation_count_clone.fetch_add(1, Ordering::SeqCst);
                (
                    Box::new(Hs256Key::random()) as Box<dyn Signer>,
                    Utc::now() + Duration::hours(1),
                )
            },
            || false, // Never auto-rotate
        );

        assert_eq!(rotation_count.load(Ordering::SeqCst), 0);

        // Force rotation
        rotator.force_rotate();
        assert_eq!(rotation_count.load(Ordering::SeqCst), 1);

        // Force again
        rotator.force_rotate();
        assert_eq!(rotation_count.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn test_rotator_concurrent_access() {
        use std::sync::Arc;
        use std::thread;

        let rotator = Arc::new(Rotator::new(
            Box::new(Hs256Key::random()),
            || {
                (
                    Box::new(Hs256Key::random()) as Box<dyn Signer>,
                    Utc::now() + Duration::hours(1),
                )
            },
            || false,
        ));

        let mut handles = vec![];

        // Spawn multiple threads accessing the rotator
        for _ in 0..10 {
            let rotator_clone = rotator.clone();
            let handle = thread::spawn(move || {
                let header = Header::new("HS256", None);
                let payload = r#"{"test":true}"#;
                for _ in 0..100 {
                    let _ = rotator_clone.sign(&header, payload);
                }
            });
            handles.push(handle);
        }

        // Wait for all threads
        for handle in handles {
            handle.join().unwrap();
        }
    }
}
