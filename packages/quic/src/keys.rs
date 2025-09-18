//! Ephemeral key material for QUIC transport with post-quantum support
use crate::CryptoTransportError;
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

/// Ephemeral key material with automatic expiration
/// NOTE: Library code - intended for external use
#[allow(dead_code)]
pub struct EphemeralKeyMaterial {
    /// Pre-shared key for additional authentication
    pub psk: Zeroizing<Vec<u8>>,
    /// Session identifier
    pub session_id: String,
    /// Creation timestamp
    created_at: Instant,
    /// Time-to-live duration
    ttl: Duration,
}

#[allow(dead_code)]
impl EphemeralKeyMaterial {
    /// Create new ephemeral key material
    pub fn new(psk: Vec<u8>, session_id: String, ttl: Duration) -> Self {
        Self {
            psk: Zeroizing::new(psk),
            session_id,
            created_at: Instant::now(),
            ttl,
        }
    }

    /// Check if key material has expired
    pub fn is_expired(&self) -> bool {
        self.created_at.elapsed() > self.ttl
    }

    /// Get remaining time to live
    pub fn remaining_ttl(&self) -> Duration {
        self.ttl.saturating_sub(self.created_at.elapsed())
    }

    /// Rotate the PSK material
    pub fn rotate(&mut self, new_psk: Vec<u8>) -> Result<(), CryptoTransportError> {
        if self.is_expired() {
            return Err(CryptoTransportError::Internal(
                "Key material has expired".to_string(),
            ));
        }
        self.psk = Zeroizing::new(new_psk);
        self.created_at = Instant::now();
        Ok(())
    }
}

/// Generate ephemeral key material using quantum-resistant KDF
/// NOTE: Library code - intended for external use
#[allow(dead_code)]
pub fn generate_ephemeral_keys(session_id: &str) -> EphemeralKeyMaterial {
    // Generate 512-bit PSK for post-quantum resistance using cryptographically secure RNG
    use rand::RngCore;
    let mut psk = vec![0u8; 64];
    rand::rng().fill_bytes(&mut psk);

    // 15-minute TTL for ephemeral keys
    let ttl = Duration::from_secs(15 * 60);

    EphemeralKeyMaterial::new(psk, session_id.to_string(), ttl)
}

/// Key manager for handling ephemeral key lifecycle
/// NOTE: Library code - intended for external use
#[allow(dead_code)]
pub struct KeyManager {
    current_keys: Option<EphemeralKeyMaterial>,
}

#[allow(dead_code)]
impl KeyManager {
    /// Create new key manager
    pub fn new() -> Self {
        Self { current_keys: None }
    }

    /// Initialize with new ephemeral keys
    pub fn initialize(&mut self, session_id: &str) {
        let keys = generate_ephemeral_keys(session_id);
        self.current_keys = Some(keys);
    }

    /// Get current keys if not expired
    pub fn get_current_keys(&self) -> Option<&EphemeralKeyMaterial> {
        self.current_keys.as_ref().filter(|k| !k.is_expired())
    }

    /// Check if keys need rotation
    pub fn needs_rotation(&self) -> bool {
        self.current_keys
            .as_ref()
            .is_none_or(|k| k.is_expired() || k.remaining_ttl() < Duration::from_secs(5 * 60))
    }

    /// Rotate keys if needed
    pub fn maybe_rotate(&mut self, session_id: &str) -> bool {
        if self.needs_rotation() {
            self.initialize(session_id);
            true
        } else {
            false
        }
    }
}
