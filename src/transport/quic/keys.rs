//! Ephemeral key material for QUIC transport with post-quantum support
use crate::CryptError;
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
    pub fn rotate(&mut self, new_psk: Vec<u8>) -> Result<(), CryptError> {
        if self.is_expired() {
            return Err(CryptError::internal("Key material has expired"));
        }
        self.psk = Zeroizing::new(new_psk);
        self.created_at = Instant::now();
        Ok(())
    }
}

/// Generate ephemeral key material using quantum-resistant KDF
pub fn generate_ephemeral_keys(session_id: &str) -> Result<EphemeralKeyMaterial, CryptError> {
    use rand::Rng;
    
    // Generate 512-bit PSK for post-quantum resistance
    let mut psk = vec![0u8; 64];
    rand::rng().fill(&mut psk);
    
    // 15-minute TTL for ephemeral keys
    let ttl = Duration::from_secs(15 * 60);
    
    Ok(EphemeralKeyMaterial::new(
        psk,
        session_id.to_string(),
        ttl
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_ephemeral_key_expiration() {
        let psk = vec![0u8; 64];
        let key = EphemeralKeyMaterial::new(
            psk,
            "test-session".to_string(),
            Duration::from_millis(50)
        );
        
        assert!(!key.is_expired());
        thread::sleep(Duration::from_millis(60));
        assert!(key.is_expired());
    }

    #[test]
    fn test_key_rotation() {
        let psk = vec![0u8; 64];
        let mut key = EphemeralKeyMaterial::new(
            psk.clone(),
            "test-session".to_string(),
            Duration::from_secs(60)
        );
        
        let new_psk = vec![1u8; 64];
        assert!(key.rotate(new_psk).is_ok());
        assert_ne!(&*key.psk, &psk);
    }
}