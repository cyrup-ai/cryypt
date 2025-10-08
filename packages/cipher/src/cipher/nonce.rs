//! Cryptographically secure nonce generation with replay protection
//!
//! Based on production-tested `secure_nonce` implementation with:
//! - Timestamp-based uniqueness guarantees
//! - HMAC authentication to prevent tampering
//! - Replay attack protection via `DashMap` cache
//! - Proper entropy from OS CSPRNG
//! - Domain-separated key derivation

use crate::{CryptError, Result};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use dashmap::DashMap;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::{CryptoRng, RngCore, rng};
use sha3::Sha3_512;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

/// Nonce structure sizes
pub const TIMESTAMP_BYTES: usize = 8; // u64 nanoseconds
pub const RANDOM_BYTES: usize = 32; // 256-bit entropy
pub const MAC_BYTES: usize = 32; // 256-bit HMAC tag
pub const NONCE_BYTES: usize = TIMESTAMP_BYTES + RANDOM_BYTES + MAC_BYTES; // 72
/// Base64url length (no padding) for 72 raw bytes = 96
pub const ENCODED_LEN: usize = 96;

const HKDF_INFO_HMAC: &[u8] = b"crypt:nonce:hmac:v1";

type HmacSha3 = Hmac<Sha3_512>;

/// Secure master key for nonce generation
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct NonceSecretKey(Zeroizing<[u8; 64]>);

impl NonceSecretKey {
    /// Generate a fresh 512-bit master secret
    #[must_use]
    pub fn generate() -> Self {
        let mut bytes = Zeroizing::new([0u8; 64]);
        rng().fill_bytes(&mut bytes[..]);
        Self(bytes)
    }

    /// Build from existing 64-byte material
    #[must_use]
    pub fn from_bytes(bytes: [u8; 64]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }
}

/// Opaque nonce type (base64url encoded)
#[derive(Clone, Eq, PartialEq, Hash)]
pub struct Nonce(String);

impl core::fmt::Debug for Nonce {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Nonce(REDACTED)")
    }
}

impl Nonce {
    /// Convert the nonce to a string representation
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Parsed nonce returned on successful verification
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParsedNonce {
    /// Timestamp in nanoseconds since Unix epoch
    pub timestamp_ns: u64,
    /// Random bytes for entropy
    pub random: [u8; RANDOM_BYTES],
}

/// Configuration for `NonceManager`
#[derive(Clone, Copy, Debug)]
pub struct NonceConfig {
    /// Max age accepted for a nonce (default 5 minutes)
    pub ttl: Duration,
}

impl Default for NonceConfig {
    fn default() -> Self {
        Self {
            ttl: Duration::from_secs(300),
        }
    }
}

/// Nonce errors
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum NonceError {
    #[error("base64url decode failure")]
    /// Failed to decode nonce data
    Decode,
    #[error("encoded length mismatch")]
    /// Nonce length does not match expected size
    LengthMismatch,
    #[error("authentication tag mismatch")]
    /// Message authentication code verification failed
    BadMac,
    #[error("nonce expired")]
    /// Nonce has expired based on timestamp
    Expired,
    #[error("replay detected")]
    /// Nonce has been used before (replay attack detected)
    Replay,
}

impl From<NonceError> for CryptError {
    fn from(err: NonceError) -> Self {
        CryptError::InvalidNonce(err.to_string())
    }
}

/// Nonce manager with replay protection
pub struct NonceManager {
    mac_key: Zeroizing<[u8; 64]>,
    cfg: NonceConfig,
    seen: DashMap<[u8; MAC_BYTES], u64>, // tag → timestamp_ns
}

impl NonceManager {
    /// Construct a manager from a master `SecretKey` and optional Config
    /// Construct a manager from a master `SecretKey` and optional Config
    ///
    /// # Errors
    ///
    /// Returns an error if the master key is invalid or configuration is malformed.
    pub fn new(master: &NonceSecretKey, cfg: Option<NonceConfig>) -> crate::error::Result<Self> {
        use crate::error::CipherError;

        // Domain-separated MAC key via HKDF-SHA3-512
        let hk = Hkdf::<Sha3_512>::new(None, master.as_bytes());
        let mut okm = Zeroizing::new([0u8; 64]);
        hk.expand(HKDF_INFO_HMAC, &mut okm[..])
            .map_err(|e| CipherError::HkdfExpansion(format!("HKDF expand failed: {e}")))?;

        Ok(Self {
            mac_key: okm,
            cfg: cfg.unwrap_or_default(),
            seen: DashMap::with_capacity(4096),
        })
    }

    /// Generate a fresh nonce using the supplied CSPRNG
    /// Generate a new cryptographically secure nonce
    ///
    /// # Errors
    ///
    /// Returns an error if random number generation fails or nonce construction fails.
    pub fn generate<'a, R>(&'a self, rng: &'a mut R) -> Result<Nonce>
    where
        R: RngCore + CryptoRng,
    {
        let ts = unix_time_nanos()?;
        let mut random = [0u8; RANDOM_BYTES];
        rng.fill_bytes(&mut random);

        let tag = self.hmac_tag(ts, &random)?;

        // Assemble raw bytes
        let mut raw = [0u8; NONCE_BYTES];
        raw[..TIMESTAMP_BYTES].copy_from_slice(&ts.to_be_bytes());
        raw[TIMESTAMP_BYTES..TIMESTAMP_BYTES + RANDOM_BYTES].copy_from_slice(&random);
        raw[TIMESTAMP_BYTES + RANDOM_BYTES..].copy_from_slice(&tag);

        let encoded = URL_SAFE_NO_PAD.encode(raw);
        Ok(Nonce(encoded))
    }

    /// Convenience wrapper using `rand::rng()`
    /// Convenience wrapper using `rand::rng()`
    ///
    /// # Errors
    ///
    /// Returns an error if OS random number generation fails or nonce construction fails.
    pub fn generate_os(&self) -> Result<Nonce> {
        self.generate(&mut rng())
    }

    /// Verify nonce authenticity, freshness and replay
    /// Verify a nonce string and check for replay attacks
    ///
    /// # Errors
    ///
    /// Returns an error if the nonce is invalid, expired, replayed, or has bad MAC.
    pub fn verify(&self, encoded: &str) -> Result<ParsedNonce> {
        // Strict length check before decode
        if encoded.len() != ENCODED_LEN {
            return Err(NonceError::LengthMismatch.into());
        }

        // Decode base64url (no pad)
        let mut raw = [0u8; NONCE_BYTES];
        URL_SAFE_NO_PAD
            .decode_slice(encoded.as_bytes(), &mut raw)
            .map_err(|_| NonceError::Decode)?;

        let ts_bytes = &raw[..TIMESTAMP_BYTES];
        let rand_bytes = &raw[TIMESTAMP_BYTES..TIMESTAMP_BYTES + RANDOM_BYTES];
        let tag_bytes = &raw[TIMESTAMP_BYTES + RANDOM_BYTES..];

        let ts = u64::from_be_bytes(ts_bytes.try_into().map_err(|_| NonceError::Decode)?);
        let mut rand_arr = [0u8; RANDOM_BYTES];
        rand_arr.copy_from_slice(rand_bytes);
        let mut tag_arr = [0u8; MAC_BYTES];
        tag_arr.copy_from_slice(tag_bytes);

        // 1. Constant-time MAC verification
        let expected_tag = self.hmac_tag(ts, &rand_arr)?;
        if expected_tag.ct_eq(&tag_arr).unwrap_u8() == 0 {
            return Err(NonceError::BadMac.into());
        }

        // 2. Freshness / TTL check
        if !is_fresh(ts, self.cfg.ttl) {
            return Err(NonceError::Expired.into());
        }

        // 3. Replay cache check
        {
            use dashmap::mapref::entry::Entry;
            match self.seen.entry(tag_arr) {
                Entry::Occupied(mut o) => {
                    // Tag seen before → replay
                    if is_fresh(*o.get(), self.cfg.ttl) {
                        return Err(NonceError::Replay.into());
                    }
                    // Expired entry; replace timestamp
                    o.insert(ts);
                }
                Entry::Vacant(v) => {
                    v.insert(ts);
                }
            }
        }

        Ok(ParsedNonce {
            timestamp_ns: ts,
            random: rand_arr,
        })
    }

    /// Extract raw nonce bytes for cipher operations (12 bytes for AES-GCM/ChaCha20)
    /// Extract cipher nonce from validated nonce
    ///
    /// # Errors
    ///
    /// Returns an error if the nonce format is invalid or cannot be processed.
    pub fn extract_cipher_nonce(&self, nonce: &Nonce) -> Result<[u8; 12]> {
        // Verify the nonce first
        let parsed = self.verify(nonce.as_str())?;

        // Use first 8 bytes of timestamp + first 4 bytes of random
        let mut cipher_nonce = [0u8; 12];
        cipher_nonce[..8].copy_from_slice(&parsed.timestamp_ns.to_be_bytes());
        cipher_nonce[8..].copy_from_slice(&parsed.random[..4]);

        Ok(cipher_nonce)
    }

    /// Compute HMAC-SHA3 tag for (timestamp, random)
    fn hmac_tag(
        &self,
        ts: u64,
        rand: &[u8; RANDOM_BYTES],
    ) -> crate::error::Result<[u8; MAC_BYTES]> {
        use crate::error::CipherError;

        let mut mac = HmacSha3::new_from_slice(&self.mac_key[..])
            .map_err(|e| CipherError::Hmac(format!("Failed to initialize HMAC: {e}")))?;
        mac.update(&ts.to_be_bytes());
        mac.update(rand);
        let mut out = [0u8; MAC_BYTES];
        out.copy_from_slice(&mac.finalize().into_bytes()[..MAC_BYTES]);
        Ok(out)
    }

    /// Clear expired entries from replay cache
    pub fn cleanup_expired(&self) {
        let now = unix_time_nanos().unwrap_or(0);
        let ttl_nanos = u64::try_from(self.cfg.ttl.as_nanos()).unwrap_or(u64::MAX);

        self.seen
            .retain(|_, &mut ts| now.saturating_sub(ts) <= ttl_nanos);
    }
}

/// Current UNIX time in nanoseconds
fn unix_time_nanos() -> crate::error::Result<u64> {
    use crate::error::CipherError;

    let dur = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| CipherError::NonceGeneration(format!("System clock error: {e}")))?;
    Ok(dur
        .as_secs()
        .saturating_mul(1_000_000_000)
        .saturating_add(u64::from(dur.subsec_nanos())))
}

/// Returns true if timestamp is within TTL of now
fn is_fresh(ts: u64, ttl: Duration) -> bool {
    let now = unix_time_nanos().unwrap_or(0);
    let age = now.saturating_sub(ts);
    age <= u64::try_from(ttl.as_nanos().min(u128::from(u64::MAX))).unwrap_or(u64::MAX)
}

/// Simple nonce generator for backward compatibility
pub struct NonceGenerator;

impl NonceGenerator {
    /// Generate a simple random nonce without authentication
    /// WARNING: This does not provide replay protection!
    #[must_use]
    pub fn simple(size: usize) -> Zeroizing<Vec<u8>> {
        let mut nonce = Zeroizing::new(vec![0u8; size]);
        rng().fill_bytes(&mut nonce);
        nonce
    }
}
