// =========================================
// === src/auth/jwt_secure.rs            ===
// =========================================

#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Fully‐featured, production-ready JWT framework.
//!
//! * Zero-copy, immutable builders with typestate.
//! * Pluggable signing back-ends (HS256 & ES256 included).
//! * Constant-time secret handling (`zeroize`).
//! * Key-rotation & revocation layers, both thread-safe.
//! * Fully async-ready with concrete Future types.
//!
//! Compile on **stable Rust 1.78+**.

use arc_swap::ArcSwap;
use chrono::{DateTime, Duration, Utc};
use dashmap::DashMap;
use hmac::{Hmac, Mac};
use once_cell::sync::Lazy;
use p256::{
    ecdsa::{SigningKey, VerifyingKey, signature::Signer as _, signature::Verifier as _},
    elliptic_curve::rand_core::OsRng,
    pkcs8::EncodePublicKey,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::Sha256;
use std::hash::BuildHasherDefault;
use std::{
    collections::HashMap,
    future::Future,
    marker::PhantomData,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use thiserror::Error;
use tokio::sync::{RwLock, oneshot};
use zeroize::{Zeroize, ZeroizeOnDrop};

// -----------------------------------------------------------------------------
// Error
// -----------------------------------------------------------------------------

/// Unified error type.
#[derive(Debug, Error)]
pub enum JwtError {
    /// Signing / verification failure.
    #[error("crypto error: {0}")]
    Crypto(String),
    /// Invalid token format.
    #[error("invalid token")]
    Malformed,
    /// Token expired.
    #[error("token expired")]
    Expired,
    /// Token not yet valid.
    #[error("token not yet valid")]
    NotYetValid,
    /// Invalid signature.
    #[error("invalid signature")]
    InvalidSignature,
    /// Revoked token.
    #[error("revoked token")]
    Revoked,
    /// Algorithm mismatch.
    #[error("algorithm mismatch: expected {expected}, got {got}")]
    AlgorithmMismatch {
        /// Expected algorithm
        expected: String,
        /// Actual algorithm in token
        got: String,
    },
    /// Missing required claim.
    #[error("missing required claim: {0}")]
    MissingClaim(String),
    /// Invalid audience.
    #[error("invalid audience")]
    InvalidAudience,
    /// Invalid issuer.
    #[error("invalid issuer")]
    InvalidIssuer,
    /// Task join error.
    #[error("task join error")]
    TaskJoinError,
}

// -----------------------------------------------------------------------------
// Typestate builder – Claims
// -----------------------------------------------------------------------------

mod ts {
    pub struct Set;
    pub struct Unset;
}

/// Immutable JWT claims.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    /// Subject.
    pub sub: String,
    /// Expiry (unix seconds).
    pub exp: i64,
    /// Issued-at (unix seconds).
    pub iat: i64,
    /// Issuer.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,
    /// Audience.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<Vec<String>>,
    /// Not before (unix seconds).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nbf: Option<i64>,
    /// JWT ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
    /// Custom data.
    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}

/// Compile-time checked builder.
pub struct ClaimsBuilder<Sub = ts::Unset, Exp = ts::Unset, Iat = ts::Unset> {
    sub: Option<String>,
    exp: Option<i64>,
    iat: Option<i64>,
    iss: Option<String>,
    aud: Option<Vec<String>>,
    nbf: Option<i64>,
    jti: Option<String>,
    extra: HashMap<String, Value>,
    _phantom: PhantomData<(Sub, Exp, Iat)>,
}

impl ClaimsBuilder {
    /// Create a new claims builder.
    pub fn new() -> Self {
        Self {
            sub: None,
            exp: None,
            iat: None,
            iss: None,
            aud: None,
            nbf: None,
            jti: None,
            extra: HashMap::new(),
            _phantom: PhantomData,
        }
    }
}

impl<Exp, Iat> ClaimsBuilder<ts::Unset, Exp, Iat> {
    /// Set the subject (sub) claim.
    pub fn subject(self, sub: impl Into<String>) -> ClaimsBuilder<ts::Set, Exp, Iat> {
        ClaimsBuilder {
            sub: Some(sub.into()),
            exp: self.exp,
            iat: self.iat,
            iss: self.iss,
            aud: self.aud,
            nbf: self.nbf,
            jti: self.jti,
            extra: self.extra,
            _phantom: PhantomData,
        }
    }
}

impl<Sub, Iat> ClaimsBuilder<Sub, ts::Unset, Iat> {
    /// Set the expiration time relative to now.
    pub fn expires_in(self, dur: Duration) -> ClaimsBuilder<Sub, ts::Set, Iat> {
        ClaimsBuilder {
            sub: self.sub,
            exp: Some((Utc::now() + dur).timestamp()),
            iat: self.iat,
            iss: self.iss,
            aud: self.aud,
            nbf: self.nbf,
            jti: self.jti,
            extra: self.extra,
            _phantom: PhantomData,
        }
    }
}

impl<Sub, Exp> ClaimsBuilder<Sub, Exp, ts::Unset> {
    /// Set the issued-at time to now.
    pub fn issued_now(self) -> ClaimsBuilder<Sub, Exp, ts::Set> {
        ClaimsBuilder {
            sub: self.sub,
            exp: self.exp,
            iat: Some(Utc::now().timestamp()),
            iss: self.iss,
            aud: self.aud,
            nbf: self.nbf,
            jti: self.jti,
            extra: self.extra,
            _phantom: PhantomData,
        }
    }
}

impl<Sub, Exp, Iat> ClaimsBuilder<Sub, Exp, Iat> {
    /// Add a custom claim.
    pub fn claim(mut self, k: impl Into<String>, v: Value) -> Self {
        self.extra.insert(k.into(), v);
        self
    }

    /// Set the issuer (iss) claim.
    pub fn issuer(mut self, iss: impl Into<String>) -> Self {
        self.iss = Some(iss.into());
        self
    }

    /// Set the audience (aud) claim.
    pub fn audience(mut self, aud: Vec<String>) -> Self {
        self.aud = Some(aud);
        self
    }

    /// Set the not-before (nbf) claim.
    pub fn not_before(mut self, nbf: DateTime<Utc>) -> Self {
        self.nbf = Some(nbf.timestamp());
        self
    }

    /// Set the JWT ID (jti) claim.
    pub fn jwt_id(mut self, jti: impl Into<String>) -> Self {
        self.jti = Some(jti.into());
        self
    }
}

impl ClaimsBuilder<ts::Set, ts::Set, ts::Set> {
    /// Build the claims. All required fields must be set.
    pub fn build(self) -> Claims {
        Claims {
            sub: match self.sub {
                Some(val) => val,
                None => panic!("Subject must be set before building Claims"),
            },
            exp: match self.exp {
                Some(val) => val,
                None => panic!("Expiry must be set before building Claims"),
            },
            iat: match self.iat {
                Some(val) => val,
                None => panic!("Issued-at must be set before building Claims"),
            },
            iss: self.iss,
            aud: self.aud,
            nbf: self.nbf,
            jti: self.jti,
            extra: self.extra,
        }
    }
}

// -----------------------------------------------------------------------------
// Validation Options
// -----------------------------------------------------------------------------

/// JWT validation options.
#[derive(Debug, Clone)]
pub struct ValidationOptions {
    /// Leeway for time-based claims.
    pub leeway: Duration,
    /// Validate expiry.
    pub validate_exp: bool,
    /// Validate not-before.
    pub validate_nbf: bool,
    /// Required claims.
    pub required_claims: Vec<String>,
    /// Allowed algorithms.
    pub allowed_algorithms: Vec<&'static str>,
    /// Expected issuer.
    pub expected_issuer: Option<String>,
    /// Expected audience.
    pub expected_audience: Option<Vec<String>>,
}

impl Default for ValidationOptions {
    fn default() -> Self {
        Self {
            leeway: Duration::seconds(60),
            validate_exp: true,
            validate_nbf: true,
            required_claims: vec![],
            allowed_algorithms: vec!["HS256", "ES256"],
            expected_issuer: None,
            expected_audience: None,
        }
    }
}

// -----------------------------------------------------------------------------
// Sign / Verify abstraction
// -----------------------------------------------------------------------------

/// Result alias.
pub type JwtResult<T> = Result<T, JwtError>;

/// Signing algorithm interface.
pub trait Signer: Send + Sync + 'static {
    /// Sign opaque payload → token (base64url header.payload.signature).
    fn sign(&self, header: &Header, payload: &str) -> JwtResult<String>;
    /// Verify token & return payload.
    fn verify(&self, token: &str) -> JwtResult<String>;
    /// Header `alg` value.
    fn alg(&self) -> &'static str;
    /// Key ID.
    fn kid(&self) -> Option<String>;
}

/// JWT header (minimal).
#[derive(Debug, Serialize, Deserialize)]
pub struct Header {
    alg: String,
    typ: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    kid: Option<String>,
}

impl Header {
    fn new(alg: &'static str, kid: Option<String>) -> Self {
        Self {
            alg: alg.to_string(),
            typ: "JWT",
            kid,
        }
    }
}

// -----------------------------------------------------------------------------
// Concrete Future Types
// -----------------------------------------------------------------------------

/// Future for token generation.
pub struct TokenGenerationFuture {
    rx: oneshot::Receiver<JwtResult<String>>,
}

impl Future for TokenGenerationFuture {
    type Output = JwtResult<String>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match Pin::new(&mut self.rx).poll(cx) {
            Poll::Ready(Ok(result)) => Poll::Ready(result),
            Poll::Ready(Err(_)) => Poll::Ready(Err(JwtError::TaskJoinError)),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Future for token verification.
pub struct TokenVerificationFuture {
    rx: oneshot::Receiver<JwtResult<Claims>>,
}

impl Future for TokenVerificationFuture {
    type Output = JwtResult<Claims>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match Pin::new(&mut self.rx).poll(cx) {
            Poll::Ready(Ok(result)) => Poll::Ready(result),
            Poll::Ready(Err(_)) => Poll::Ready(Err(JwtError::TaskJoinError)),
            Poll::Pending => Poll::Pending,
        }
    }
}

// -----------------------------------------------------------------------------
// HS256 Signer (HMAC-SHA256)
// -----------------------------------------------------------------------------

/// Constant-time zeroizable secret.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Hs256Key {
    key: [u8; 32],
    kid: Option<String>,
}

impl Hs256Key {
    /// Generate a new random HS256 key.
    pub fn random() -> Self {
        let mut k = [0u8; 32];
        rand::rng().fill_bytes(&mut k);
        Self { key: k, kid: None }
    }

    /// Set the key ID for this key.
    pub fn with_kid(mut self, kid: impl Into<String>) -> Self {
        self.kid = Some(kid.into());
        self
    }
}

impl Signer for Hs256Key {
    fn sign(&self, header: &Header, payload: &str) -> JwtResult<String> {
        let header_json = match serde_json::to_string(header) {
            Ok(h) => h,
            Err(_) => return Err(JwtError::Malformed),
        };
        let data = format!(
            "{}.{}",
            base64_url::encode(&header_json),
            base64_url::encode(payload)
        );

        let mut mac = Hmac::<Sha256>::new_from_slice(&self.key)
            .map_err(|e| JwtError::Crypto(e.to_string()))?;
        mac.update(data.as_bytes());
        let sig = mac.finalize().into_bytes();
        Ok(format!("{}.{}", data, base64_url::encode(&sig)))
    }

    fn verify(&self, token: &str) -> JwtResult<String> {
        // Split token
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return Err(JwtError::Malformed);
        }

        // Parse and validate header
        let header_bytes = base64_url::decode(parts[0]).map_err(|_| JwtError::Malformed)?;

        // Parse header and extract algorithm
        let header_json = String::from_utf8(header_bytes).map_err(|_| JwtError::Malformed)?;
        let header: serde_json::Value =
            serde_json::from_str(&header_json).map_err(|_| JwtError::Malformed)?;
        let header_alg = header
            .get("alg")
            .and_then(|v| v.as_str())
            .ok_or(JwtError::Malformed)?
            .to_string();

        // Verify algorithm matches
        if header_alg != self.alg() {
            return Err(JwtError::AlgorithmMismatch {
                expected: self.alg().to_string(),
                got: header_alg,
            });
        }

        // Verify signature
        let data = format!("{}.{}", parts[0], parts[1]);
        let sig = base64_url::decode(parts[2]).map_err(|_| JwtError::Malformed)?;

        let mut mac = Hmac::<Sha256>::new_from_slice(&self.key)
            .map_err(|e| JwtError::Crypto(e.to_string()))?;
        mac.update(data.as_bytes());
        mac.verify_slice(&sig)
            .map_err(|_| JwtError::InvalidSignature)?;

        // Decode payload
        let payload_bytes = base64_url::decode(parts[1]).map_err(|_| JwtError::Malformed)?;
        let payload = String::from_utf8(payload_bytes).map_err(|_| JwtError::Malformed)?;
        Ok(payload)
    }

    fn alg(&self) -> &'static str {
        "HS256"
    }

    fn kid(&self) -> Option<String> {
        self.kid.clone()
    }
}

// -----------------------------------------------------------------------------
// ES256 Signer (P-256 ECDSA)
// -----------------------------------------------------------------------------

/// ES256 (ECDSA with P-256) signing key.
pub struct Es256Key {
    sk: SigningKey, // Zeroizes on drop
    pk: VerifyingKey,
    kid: String,
}

impl Es256Key {
    /// Generate a new ES256 key pair.
    pub fn new() -> Self {
        let sk = SigningKey::random(&mut OsRng);
        let pk = *sk.verifying_key();
        let kid = match pk.to_public_key_der() {
            Ok(der) => base64_url::encode(der.as_bytes()),
            Err(_) => panic!("Failed to encode public key DER"),
        };
        Self { sk, pk, kid }
    }

    /// Set the key ID for this key.
    pub fn with_kid(mut self, kid: impl Into<String>) -> Self {
        self.kid = kid.into();
        self
    }
}

impl Signer for Es256Key {
    fn sign(&self, header: &Header, payload: &str) -> JwtResult<String> {
        let header_json = match serde_json::to_string(header) {
            Ok(h) => h,
            Err(_) => return Err(JwtError::Malformed),
        };
        let data = format!(
            "{}.{}",
            base64_url::encode(&header_json),
            base64_url::encode(payload)
        );
        let sig: p256::ecdsa::Signature = self.sk.sign(data.as_bytes());
        // Use fixed-length encoding for JWT (not DER)
        Ok(format!("{}.{}", data, base64_url::encode(&sig.to_bytes())))
    }

    fn verify(&self, token: &str) -> JwtResult<String> {
        // Split token
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return Err(JwtError::Malformed);
        }

        // Parse and validate header
        let header_bytes = base64_url::decode(parts[0]).map_err(|_| JwtError::Malformed)?;

        // Parse header and extract algorithm
        let header_json = String::from_utf8(header_bytes).map_err(|_| JwtError::Malformed)?;
        let header: serde_json::Value =
            serde_json::from_str(&header_json).map_err(|_| JwtError::Malformed)?;
        let header_alg = header
            .get("alg")
            .and_then(|v| v.as_str())
            .ok_or(JwtError::Malformed)?
            .to_string();

        // Verify algorithm matches
        if header_alg != self.alg() {
            return Err(JwtError::AlgorithmMismatch {
                expected: self.alg().to_string(),
                got: header_alg,
            });
        }

        // Verify signature
        let data = format!("{}.{}", parts[0], parts[1]);
        let sig_bytes = base64_url::decode(parts[2]).map_err(|_| JwtError::Malformed)?;
        let sig =
            p256::ecdsa::Signature::from_slice(&sig_bytes).map_err(|_| JwtError::Malformed)?;

        self.pk
            .verify(data.as_bytes(), &sig)
            .map_err(|_| JwtError::InvalidSignature)?;

        // Decode payload
        let payload_bytes = base64_url::decode(parts[1]).map_err(|_| JwtError::Malformed)?;
        let payload = String::from_utf8(payload_bytes).map_err(|_| JwtError::Malformed)?;
        Ok(payload)
    }

    fn alg(&self) -> &'static str {
        "ES256"
    }

    fn kid(&self) -> Option<String> {
        Some(self.kid.clone())
    }
}

// -----------------------------------------------------------------------------
// Token generator with rotation + revocation decorators
// -----------------------------------------------------------------------------

/// Core generator.
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

        TokenGenerationFuture { rx }
    }

    /// Verify a JWT token and extract claims.
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
                if options.validate_exp && claims.exp < now - leeway {
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

        TokenVerificationFuture { rx }
    }
}

// -----------------------------------------------------------------------------
// Key-rotation layer
// -----------------------------------------------------------------------------

/// Thread-safe, immutable key rotation wrapper.
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
    pub fn new(initial: Box<dyn Signer>, next_key_fn: G, rotate_trigger: F) -> Self {
        Self {
            active: ArcSwap::from_pointee(initial),
            next_key_fn,
            rotate_trigger,
        }
    }

    fn maybe_rotate(&self) {
        if (self.rotate_trigger)() {
            let (next, _expires) = (self.next_key_fn)();
            self.active.store(Arc::new(next));
        }
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
        self.active.load().verify(token)
    }

    fn alg(&self) -> &'static str {
        self.active.load().alg()
    }

    fn kid(&self) -> Option<String> {
        self.active.load().kid()
    }
}

// -----------------------------------------------------------------------------
// Revocation layer
// -----------------------------------------------------------------------------

static HASHER: Lazy<BuildHasherDefault<twox_hash::XxHash64>> =
    Lazy::new(BuildHasherDefault::default);

/// Revoked token information.
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

/// Future for cleanup task start.
pub struct CleanupStartFuture {
    rx: oneshot::Receiver<()>,
}

impl Future for CleanupStartFuture {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match Pin::new(&mut self.rx).poll(cx) {
            Poll::Ready(_) => Poll::Ready(()),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// In-memory revocation store (token hashes).
pub struct Revocation<S: Signer> {
    inner: Arc<S>,
    revoked: Arc<DashMap<u64, RevokedToken, BuildHasherDefault<twox_hash::XxHash64>>>,
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
    pub fn start_cleanup(&self, interval: Duration) -> CleanupStartFuture {
        let (tx, rx) = oneshot::channel();
        let revoked = self.revoked.clone();
        let cleanup_task = self.cleanup_task.clone();

        tokio::spawn(async move {
            let handle = tokio::spawn(async move {
                let mut interval = tokio::time::interval(interval.to_std().unwrap());
                loop {
                    interval.tick().await;
                    let now = Utc::now();
                    revoked.retain(|_, token| token.expires_at > now);
                }
            });

            *cleanup_task.write().await = Some(handle);
            let _ = tx.send(());
        });

        CleanupStartFuture { rx }
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

    fn extract_expiry(&self, token: &str) -> JwtResult<DateTime<Utc>> {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return Err(JwtError::Malformed);
        }

        let payload_bytes = base64_url::decode(parts[1]).map_err(|_| JwtError::Malformed)?;
        let payload = String::from_utf8(payload_bytes).map_err(|_| JwtError::Malformed)?;
        let claims: Claims = serde_json::from_str(&payload).map_err(|_| JwtError::Malformed)?;

        Ok(DateTime::from_timestamp(claims.exp, 0).unwrap())
    }

    /// Generate a JWT token with the given claims using the wrapped signer.
    pub fn token(&self, claims: &Claims) -> TokenGenerationFuture {
        Generator {
            signer: self.inner.clone(),
            validation_options: ValidationOptions::default(),
        }
        .token(claims)
    }

    /// Verify a JWT token and extract claims if valid and not revoked.
    pub fn verify(&self, token: impl Into<String>) -> TokenVerificationFuture {
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

            let generator = Generator {
                signer: inner,
                validation_options: ValidationOptions::default(),
            };

            // Await the verification future
            let result = generator.verify(token_str).await;

            let _ = tx.send(result);
        });

        TokenVerificationFuture { rx }
    }

    /// Manually cleanup expired tokens.
    pub fn cleanup_expired(&self) {
        let now = Utc::now();
        self.revoked.retain(|_, token| token.expires_at > now);
    }

    fn hash(t: &str) -> u64 {
        use std::hash::{BuildHasher, Hasher};
        let mut h = (*HASHER).build_hasher();
        h.write(t.as_bytes());
        h.finish()
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
