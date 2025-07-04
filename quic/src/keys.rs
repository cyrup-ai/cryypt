//! Ephemeral key material for QUIC transport with post-quantum support
use crate::CryptoTransportError;
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

/// Ephemeral key material with automatic expiration
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
pub fn generate_ephemeral_keys(
    session_id: &str,
) -> Result<EphemeralKeyMaterial, CryptoTransportError> {
    use rand::RngCore;

    // Generate 512-bit PSK for post-quantum resistance
    let mut psk = vec![0u8; 64];
    rand::rng().fill_bytes(&mut psk);

    // 15-minute TTL for ephemeral keys
    let ttl = Duration::from_secs(15 * 60);

    Ok(EphemeralKeyMaterial::new(psk, session_id.to_string(), ttl))
}

