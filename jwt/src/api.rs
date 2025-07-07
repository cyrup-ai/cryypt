//! JWT API following README.md patterns exactly

pub mod rotator_builder;

use crate::{error::*, types::*};
use serde::Serialize;
use tokio::sync::oneshot;

/// Master builder for JWT operations - README.md pattern
pub struct JwtMasterBuilder;

impl JwtMasterBuilder {
    /// Create new JWT builder - unified entry point
    pub fn new() -> JwtBuilder {
        JwtBuilder::new()
    }
}

/// Direct builder entry point - equivalent to Cryypt::jwt()
pub struct Jwt;

impl Jwt {
    /// Create new JWT builder - unified entry point
    pub fn new() -> JwtBuilder {
        JwtBuilder::new()
    }
}

/// Unified JWT builder - follows README.md pattern
pub struct JwtBuilder {
    algorithm: Option<String>,
    secret: Option<Vec<u8>>,
    private_key: Option<Vec<u8>>,
    public_key: Option<Vec<u8>>,
}

/// JWT builder with handler - polymorphic based on usage
pub struct JwtBuilderWithHandler<F> {
    algorithm: Option<String>,
    secret: Option<Vec<u8>>,
    private_key: Option<Vec<u8>>,
    public_key: Option<Vec<u8>>,
    handler: F,
}

/// JWT builder with error handler
pub struct JwtBuilderWithError<E> {
    algorithm: Option<String>,
    secret: Option<Vec<u8>>,
    private_key: Option<Vec<u8>>,
    public_key: Option<Vec<u8>>,
    error_handler: E,
}

impl JwtBuilder {
    /// Create new JWT builder
    pub fn new() -> Self {
        Self {
            algorithm: None,
            secret: None,
            private_key: None,
            public_key: None,
        }
    }

    /// Set algorithm - README.md pattern
    #[inline]
    pub fn with_algorithm(mut self, algorithm: &str) -> Self {
        self.algorithm = Some(algorithm.to_string());
        self
    }

    /// Set secret for symmetric algorithms - README.md pattern
    #[inline]
    pub fn with_secret(mut self, secret: &[u8]) -> Self {
        self.secret = Some(secret.to_vec());
        self
    }

    /// Set private key for asymmetric algorithms - README.md pattern
    #[inline]
    pub fn with_private_key(mut self, key: &[u8]) -> Self {
        self.private_key = Some(key.to_vec());
        self
    }

    /// Set public key for asymmetric verification - README.md pattern
    #[inline]
    pub fn with_public_key(mut self, key: &[u8]) -> Self {
        self.public_key = Some(key.to_vec());
        self
    }

    /// Add on_result handler - polymorphic based on subsequent method call
    pub fn on_result<F>(self, handler: F) -> JwtBuilderWithHandler<F>
    where
        F: Send + 'static,
    {
        JwtBuilderWithHandler {
            algorithm: self.algorithm,
            secret: self.secret,
            private_key: self.private_key,
            public_key: self.public_key,
            handler,
        }
    }
    
    /// Add on_error handler - transforms errors but passes through success
    pub fn on_error<E>(self, handler: E) -> JwtBuilderWithError<E>
    where
        E: Fn(JwtError) -> JwtError + Send + Sync + 'static,
    {
        JwtBuilderWithError {
            algorithm: self.algorithm,
            secret: self.secret,
            private_key: self.private_key,
            public_key: self.public_key,
            error_handler: handler,
        }
    }

    /// Sign JWT without handler - returns AsyncJwtResult for String
    pub fn sign<C: Serialize + Send + 'static>(self, claims: C) -> AsyncJwtResult<String> {
        let algorithm = self.algorithm.unwrap_or_else(|| "HS256".to_string());
        let secret = self.secret;
        let private_key = self.private_key;
        
        let (tx, rx) = oneshot::channel();
        
        tokio::spawn(async move {
            let result = sign_jwt(algorithm, claims, secret, private_key).await;
            let _ = tx.send(result);
        });
        
        AsyncJwtResult::new(rx)
    }

    /// Verify JWT without handler - returns AsyncJwtResult for Value
    pub fn verify<S: AsRef<str>>(self, token: S) -> AsyncJwtResult<serde_json::Value> {
        let token = token.as_ref().to_string();
        let secret = self.secret;
        let public_key = self.public_key;
        
        let (tx, rx) = oneshot::channel();
        
        tokio::spawn(async move {
            let result = verify_jwt(token, secret, public_key).await;
            let _ = tx.send(result);
        });
        
        AsyncJwtResult::new(rx)
    }
}

impl<F, T> JwtBuilderWithHandler<F>
where
    F: FnOnce(Result<String, JwtError>) -> T + Send + 'static,
    T: cryypt_common::NotResult + Send + 'static,
{
    /// Sign JWT with handler - returns unwrapped type T
    pub async fn sign<C: Serialize + Send + 'static>(self, claims: C) -> T {
        let algorithm = self.algorithm.unwrap_or_else(|| "HS256".to_string());
        let result = sign_jwt(algorithm, claims, self.secret, self.private_key).await;
        (self.handler)(result)
    }
}

impl<F, T> JwtBuilderWithHandler<F>
where
    F: FnOnce(Result<serde_json::Value, JwtError>) -> T + Send + 'static,
    T: cryypt_common::NotResult + Send + 'static,
{
    /// Verify JWT with handler - returns unwrapped type T
    pub async fn verify<S: AsRef<str>>(self, token: S) -> T {
        let token = token.as_ref().to_string();
        let result = verify_jwt(token, self.secret, self.public_key).await;
        (self.handler)(result)
    }
}

impl<E> JwtBuilderWithError<E>
where
    E: Fn(JwtError) -> JwtError + Send + Sync + 'static,
{
    /// Set algorithm
    #[inline]
    pub fn with_algorithm(mut self, algorithm: &str) -> Self {
        self.algorithm = Some(algorithm.to_string());
        self
    }

    /// Set secret for symmetric algorithms
    #[inline]
    pub fn with_secret(mut self, secret: &[u8]) -> Self {
        self.secret = Some(secret.to_vec());
        self
    }

    /// Set private key for asymmetric algorithms
    #[inline]
    pub fn with_private_key(mut self, key: &[u8]) -> Self {
        self.private_key = Some(key.to_vec());
        self
    }

    /// Set public key for asymmetric verification
    #[inline]
    pub fn with_public_key(mut self, key: &[u8]) -> Self {
        self.public_key = Some(key.to_vec());
        self
    }
    
    /// Add on_result handler after error handler
    pub fn on_result<F>(self, handler: F) -> JwtBuilderWithHandler<F>
    where
        F: Send + 'static,
    {
        JwtBuilderWithHandler {
            algorithm: self.algorithm,
            secret: self.secret,
            private_key: self.private_key,
            public_key: self.public_key,
            handler,
        }
    }

    /// Sign JWT with error handler - returns AsyncJwtResult
    pub fn sign<C: Serialize + Send + 'static>(self, claims: C) -> AsyncJwtResultWithError<String, E> {
        let algorithm = self.algorithm.unwrap_or_else(|| "HS256".to_string());
        let secret = self.secret;
        let private_key = self.private_key;
        let error_handler = self.error_handler;
        
        let (tx, rx) = oneshot::channel();
        
        tokio::spawn(async move {
            let result = sign_jwt(algorithm, claims, secret, private_key).await;
            let _ = tx.send(result);
        });
        
        AsyncJwtResultWithError::new(rx, error_handler)
    }

    /// Verify JWT with error handler - returns AsyncJwtResult
    pub fn verify<S: AsRef<str>>(self, token: S) -> AsyncJwtResultWithError<serde_json::Value, E> {
        let token = token.as_ref().to_string();
        let secret = self.secret;
        let public_key = self.public_key;
        let error_handler = self.error_handler;
        
        let (tx, rx) = oneshot::channel();
        
        tokio::spawn(async move {
            let result = verify_jwt(token, secret, public_key).await;
            let _ = tx.send(result);
        });
        
        AsyncJwtResultWithError::new(rx, error_handler)
    }
}

/// Async JWT result type
pub struct AsyncJwtResult<T> {
    receiver: oneshot::Receiver<Result<T, JwtError>>,
}

impl<T> AsyncJwtResult<T> {
    fn new(receiver: oneshot::Receiver<Result<T, JwtError>>) -> Self {
        Self { receiver }
    }
}

impl<T: Send + 'static> std::future::Future for AsyncJwtResult<T> {
    type Output = Result<T, JwtError>;

    fn poll(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<Self::Output> {
        let receiver = std::pin::Pin::new(&mut self.receiver);
        match receiver.poll(cx) {
            std::task::Poll::Ready(Ok(result)) => std::task::Poll::Ready(result),
            std::task::Poll::Ready(Err(_)) => std::task::Poll::Ready(Err(JwtError::internal("JWT operation failed"))),
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}

/// Async JWT result with error handler
pub struct AsyncJwtResultWithError<T, E> {
    receiver: oneshot::Receiver<Result<T, JwtError>>,
    error_handler: E,
}

impl<T, E> AsyncJwtResultWithError<T, E> {
    fn new(receiver: oneshot::Receiver<Result<T, JwtError>>, error_handler: E) -> Self {
        Self { receiver, error_handler }
    }
}

impl<T: Send + 'static, E> std::future::Future for AsyncJwtResultWithError<T, E>
where
    E: Fn(JwtError) -> JwtError + Unpin,
{
    type Output = Result<T, JwtError>;

    fn poll(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<Self::Output> {
        let receiver = std::pin::Pin::new(&mut self.receiver);
        match receiver.poll(cx) {
            std::task::Poll::Ready(Ok(Ok(value))) => std::task::Poll::Ready(Ok(value)),
            std::task::Poll::Ready(Ok(Err(e))) => std::task::Poll::Ready(Err((self.error_handler)(e))),
            std::task::Poll::Ready(Err(_)) => std::task::Poll::Ready(Err((self.error_handler)(JwtError::internal("JWT operation failed")))),
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}

// Internal JWT operations using true async
async fn sign_jwt<C: Serialize + Send + 'static>(
    algorithm: String,
    claims: C,
    secret: Option<Vec<u8>>,
    private_key: Option<Vec<u8>>,
) -> Result<String, JwtError> {
    let (tx, rx) = oneshot::channel();
    
    std::thread::spawn(move || {
        let result = (|| {
            // Serialize claims
            let claims_value = serde_json::to_value(&claims)
                .map_err(|e| JwtError::invalid_claims(&e.to_string()))?;
            
            // Create header
            let header = JwtHeader {
                alg: algorithm.clone(),
                typ: "JWT".to_string(),
                kid: None,
            };
            
            // Encode header and payload
            let header_json = serde_json::to_string(&header)
                .map_err(|e| JwtError::internal(&e.to_string()))?;
            let payload_json = serde_json::to_string(&claims_value)
                .map_err(|e| JwtError::internal(&e.to_string()))?;
            
            let header_b64 = base64_url_encode(header_json.as_bytes());
            let payload_b64 = base64_url_encode(payload_json.as_bytes());
            
            let message = format!("{}.{}", header_b64, payload_b64);
            
            // Sign based on algorithm
            let signature = match algorithm.as_str() {
                "HS256" => {
                    let secret = secret.ok_or_else(|| JwtError::missing_key("Secret required for HS256"))?;
                    sign_hs256(&message, &secret)?
                }
                "HS384" => {
                    let secret = secret.ok_or_else(|| JwtError::missing_key("Secret required for HS384"))?;
                    sign_hs384(&message, &secret)?
                }
                "HS512" => {
                    let secret = secret.ok_or_else(|| JwtError::missing_key("Secret required for HS512"))?;
                    sign_hs512(&message, &secret)?
                }
                "RS256" => {
                    let key = private_key.ok_or_else(|| JwtError::missing_key("Private key required for RS256"))?;
                    sign_rs256(&message, &key)?
                }
                "RS384" => {
                    let key = private_key.ok_or_else(|| JwtError::missing_key("Private key required for RS384"))?;
                    sign_rs384(&message, &key)?
                }
                "RS512" => {
                    let key = private_key.ok_or_else(|| JwtError::missing_key("Private key required for RS512"))?;
                    sign_rs512(&message, &key)?
                }
                "ES256" => {
                    let key = private_key.ok_or_else(|| JwtError::missing_key("Private key required for ES256"))?;
                    sign_es256(&message, &key)?
                }
                "ES384" => {
                    let key = private_key.ok_or_else(|| JwtError::missing_key("Private key required for ES384"))?;
                    sign_es384(&message, &key)?
                }
                _ => return Err(JwtError::unsupported_algorithm(&algorithm)),
            };
            
            let signature_b64 = base64_url_encode(&signature);
            Ok(format!("{}.{}", message, signature_b64))
        })();
        
        let _ = tx.send(result);
    });
    
    rx.await.map_err(|_| JwtError::internal("JWT signing task failed"))?
}

async fn verify_jwt(
    token: String,
    secret: Option<Vec<u8>>,
    public_key: Option<Vec<u8>>,
) -> Result<serde_json::Value, JwtError> {
    let (tx, rx) = oneshot::channel();
    
    std::thread::spawn(move || {
        let result = (|| {
            // Split token
            let parts: Vec<&str> = token.split('.').collect();
            if parts.len() != 3 {
                return Err(JwtError::invalid_token("Invalid JWT format"));
            }
            
            let header_b64 = parts[0];
            let payload_b64 = parts[1];
            let signature_b64 = parts[2];
            
            // Decode header
            let header_bytes = base64_url_decode(header_b64)
                .map_err(|_| JwtError::invalid_token("Invalid header encoding"))?;
            let header: JwtHeader = serde_json::from_slice(&header_bytes)
                .map_err(|_| JwtError::invalid_token("Invalid header JSON"))?;
            
            // Decode payload
            let payload_bytes = base64_url_decode(payload_b64)
                .map_err(|_| JwtError::invalid_token("Invalid payload encoding"))?;
            let claims: serde_json::Value = serde_json::from_slice(&payload_bytes)
                .map_err(|_| JwtError::invalid_token("Invalid payload JSON"))?;
            
            // Verify signature
            let message = format!("{}.{}", header_b64, payload_b64);
            let signature = base64_url_decode(signature_b64)
                .map_err(|_| JwtError::invalid_token("Invalid signature encoding"))?;
            
            let valid = match header.alg.as_str() {
                "HS256" => {
                    let secret = secret.ok_or_else(|| JwtError::missing_key("Secret required for HS256 verification"))?;
                    verify_hs256(&message, &signature, &secret)?
                }
                "HS384" => {
                    let secret = secret.ok_or_else(|| JwtError::missing_key("Secret required for HS384 verification"))?;
                    verify_hs384(&message, &signature, &secret)?
                }
                "HS512" => {
                    let secret = secret.ok_or_else(|| JwtError::missing_key("Secret required for HS512 verification"))?;
                    verify_hs512(&message, &signature, &secret)?
                }
                "RS256" => {
                    let key = public_key.ok_or_else(|| JwtError::missing_key("Public key required for RS256 verification"))?;
                    verify_rs256(&message, &signature, &key)?
                }
                "RS384" => {
                    let key = public_key.ok_or_else(|| JwtError::missing_key("Public key required for RS384 verification"))?;
                    verify_rs384(&message, &signature, &key)?
                }
                "RS512" => {
                    let key = public_key.ok_or_else(|| JwtError::missing_key("Public key required for RS512 verification"))?;
                    verify_rs512(&message, &signature, &key)?
                }
                "ES256" => {
                    let key = public_key.ok_or_else(|| JwtError::missing_key("Public key required for ES256 verification"))?;
                    verify_es256(&message, &signature, &key)?
                }
                "ES384" => {
                    let key = public_key.ok_or_else(|| JwtError::missing_key("Public key required for ES384 verification"))?;
                    verify_es384(&message, &signature, &key)?
                }
                _ => return Err(JwtError::unsupported_algorithm(&header.alg)),
            };
            
            if !valid {
                return Err(JwtError::invalid_signature());
            }
            
            // Validate claims
            validate_standard_claims(&claims)?;
            
            Ok(claims)
        })();
        
        let _ = tx.send(result);
    });
    
    rx.await.map_err(|_| JwtError::internal("JWT verification task failed"))?
}

// Efficient base64 URL encoding
#[inline]
fn base64_url_encode(input: &[u8]) -> String {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    URL_SAFE_NO_PAD.encode(input)
}

// Efficient base64 URL decoding
#[inline]
fn base64_url_decode(input: &str) -> Result<Vec<u8>, base64::DecodeError> {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    URL_SAFE_NO_PAD.decode(input)
}

// HMAC-SHA256 signing
fn sign_hs256(message: &str, secret: &[u8]) -> Result<Vec<u8>, JwtError> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    
    let mut mac = Hmac::<Sha256>::new_from_slice(secret)
        .map_err(|_| JwtError::invalid_key("Invalid HMAC key"))?;
    mac.update(message.as_bytes());
    Ok(mac.finalize().into_bytes().to_vec())
}

// HMAC-SHA384 signing
fn sign_hs384(message: &str, secret: &[u8]) -> Result<Vec<u8>, JwtError> {
    use hmac::{Hmac, Mac};
    use sha2::Sha384;
    
    let mut mac = Hmac::<Sha384>::new_from_slice(secret)
        .map_err(|_| JwtError::invalid_key("Invalid HMAC key"))?;
    mac.update(message.as_bytes());
    Ok(mac.finalize().into_bytes().to_vec())
}

// HMAC-SHA512 signing
fn sign_hs512(message: &str, secret: &[u8]) -> Result<Vec<u8>, JwtError> {
    use hmac::{Hmac, Mac};
    use sha2::Sha512;
    
    let mut mac = Hmac::<Sha512>::new_from_slice(secret)
        .map_err(|_| JwtError::invalid_key("Invalid HMAC key"))?;
    mac.update(message.as_bytes());
    Ok(mac.finalize().into_bytes().to_vec())
}

// HMAC verification
fn verify_hs256(message: &str, signature: &[u8], secret: &[u8]) -> Result<bool, JwtError> {
    let expected = sign_hs256(message, secret)?;
    Ok(constant_time_eq(&expected, signature))
}

fn verify_hs384(message: &str, signature: &[u8], secret: &[u8]) -> Result<bool, JwtError> {
    let expected = sign_hs384(message, secret)?;
    Ok(constant_time_eq(&expected, signature))
}

fn verify_hs512(message: &str, signature: &[u8], secret: &[u8]) -> Result<bool, JwtError> {
    let expected = sign_hs512(message, secret)?;
    Ok(constant_time_eq(&expected, signature))
}

// RSA signing using rsa crate
fn sign_rs256(message: &str, private_key_der: &[u8]) -> Result<Vec<u8>, JwtError> {
    use rsa::{RsaPrivateKey, pkcs8::DecodePrivateKey, Pkcs1v15Sign};
    use sha2::{Sha256, Digest};
    
    let key = RsaPrivateKey::from_pkcs8_der(private_key_der)
        .map_err(|e| JwtError::invalid_key(&format!("Invalid RSA private key: {}", e)))?;
    
    let mut hasher = Sha256::new();
    hasher.update(message.as_bytes());
    let hash = hasher.finalize();
    
    key.sign(Pkcs1v15Sign::new_unprefixed(), &hash)
        .map_err(|e| JwtError::signing_error(&format!("RSA signing failed: {}", e)))
}

fn sign_rs384(message: &str, private_key_der: &[u8]) -> Result<Vec<u8>, JwtError> {
    use rsa::{RsaPrivateKey, pkcs8::DecodePrivateKey, Pkcs1v15Sign};
    use sha2::{Sha384, Digest};
    
    let key = RsaPrivateKey::from_pkcs8_der(private_key_der)
        .map_err(|e| JwtError::invalid_key(&format!("Invalid RSA private key: {}", e)))?;
    
    let mut hasher = Sha384::new();
    hasher.update(message.as_bytes());
    let hash = hasher.finalize();
    
    key.sign(Pkcs1v15Sign::new_unprefixed(), &hash)
        .map_err(|e| JwtError::signing_error(&format!("RSA signing failed: {}", e)))
}

fn sign_rs512(message: &str, private_key_der: &[u8]) -> Result<Vec<u8>, JwtError> {
    use rsa::{RsaPrivateKey, pkcs8::DecodePrivateKey, Pkcs1v15Sign};
    use sha2::{Sha512, Digest};
    
    let key = RsaPrivateKey::from_pkcs8_der(private_key_der)
        .map_err(|e| JwtError::invalid_key(&format!("Invalid RSA private key: {}", e)))?;
    
    let mut hasher = Sha512::new();
    hasher.update(message.as_bytes());
    let hash = hasher.finalize();
    
    key.sign(Pkcs1v15Sign::new_unprefixed(), &hash)
        .map_err(|e| JwtError::signing_error(&format!("RSA signing failed: {}", e)))
}

// RSA verification
fn verify_rs256(message: &str, signature: &[u8], public_key_der: &[u8]) -> Result<bool, JwtError> {
    use rsa::{RsaPublicKey, pkcs8::DecodePublicKey, Pkcs1v15Sign};
    use sha2::{Sha256, Digest};
    
    let key = RsaPublicKey::from_public_key_der(public_key_der)
        .map_err(|e| JwtError::invalid_key(&format!("Invalid RSA public key: {}", e)))?;
    
    let mut hasher = Sha256::new();
    hasher.update(message.as_bytes());
    let hash = hasher.finalize();
    
    key.verify(Pkcs1v15Sign::new_unprefixed(), &hash, signature)
        .map(|_| true)
        .or_else(|_| Ok(false))
}

fn verify_rs384(message: &str, signature: &[u8], public_key_der: &[u8]) -> Result<bool, JwtError> {
    use rsa::{RsaPublicKey, pkcs8::DecodePublicKey, Pkcs1v15Sign};
    use sha2::{Sha384, Digest};
    
    let key = RsaPublicKey::from_public_key_der(public_key_der)
        .map_err(|e| JwtError::invalid_key(&format!("Invalid RSA public key: {}", e)))?;
    
    let mut hasher = Sha384::new();
    hasher.update(message.as_bytes());
    let hash = hasher.finalize();
    
    key.verify(Pkcs1v15Sign::new_unprefixed(), &hash, signature)
        .map(|_| true)
        .or_else(|_| Ok(false))
}

fn verify_rs512(message: &str, signature: &[u8], public_key_der: &[u8]) -> Result<bool, JwtError> {
    use rsa::{RsaPublicKey, pkcs8::DecodePublicKey, Pkcs1v15Sign};
    use sha2::{Sha512, Digest};
    
    let key = RsaPublicKey::from_public_key_der(public_key_der)
        .map_err(|e| JwtError::invalid_key(&format!("Invalid RSA public key: {}", e)))?;
    
    let mut hasher = Sha512::new();
    hasher.update(message.as_bytes());
    let hash = hasher.finalize();
    
    key.verify(Pkcs1v15Sign::new_unprefixed(), &hash, signature)
        .map(|_| true)
        .or_else(|_| Ok(false))
}

// ECDSA P-256 signing
fn sign_es256(message: &str, private_key_der: &[u8]) -> Result<Vec<u8>, JwtError> {
    use p256::{
        ecdsa::{signature::Signer, Signature, SigningKey},
        pkcs8::DecodePrivateKey,
    };
    use sha2::{Sha256, Digest};
    
    let signing_key = SigningKey::from_pkcs8_der(private_key_der)
        .map_err(|e| JwtError::invalid_key(&format!("Invalid EC private key: {}", e)))?;
    
    let mut hasher = Sha256::new();
    hasher.update(message.as_bytes());
    let hash = hasher.finalize();
    
    let signature: Signature = signing_key.sign(&hash);
    Ok(signature.to_der().as_bytes().to_vec())
}

// ECDSA P-384 signing  
fn sign_es384(message: &str, private_key_der: &[u8]) -> Result<Vec<u8>, JwtError> {
    use p384::{
        ecdsa::{signature::Signer, Signature, SigningKey},
        pkcs8::DecodePrivateKey,
    };
    use sha2::{Sha384, Digest};
    
    let signing_key = SigningKey::from_pkcs8_der(private_key_der)
        .map_err(|e| JwtError::invalid_key(&format!("Invalid EC private key: {}", e)))?;
    
    let mut hasher = Sha384::new();
    hasher.update(message.as_bytes());
    let hash = hasher.finalize();
    
    let signature: Signature = signing_key.sign(&hash);
    Ok(signature.to_der().as_bytes().to_vec())
}

// ECDSA verification
fn verify_es256(message: &str, signature: &[u8], public_key_der: &[u8]) -> Result<bool, JwtError> {
    use p256::{
        ecdsa::{signature::Verifier, Signature, VerifyingKey},
        pkcs8::DecodePublicKey,
    };
    use sha2::{Sha256, Digest};
    
    let verifying_key = VerifyingKey::from_public_key_der(public_key_der)
        .map_err(|e| JwtError::invalid_key(&format!("Invalid EC public key: {}", e)))?;
    
    let signature = Signature::from_der(signature)
        .map_err(|_e| JwtError::invalid_signature())?;
    
    let mut hasher = Sha256::new();
    hasher.update(message.as_bytes());
    let hash = hasher.finalize();
    
    verifying_key.verify(&hash, &signature)
        .map(|_| true)
        .or_else(|_| Ok(false))
}

fn verify_es384(message: &str, signature: &[u8], public_key_der: &[u8]) -> Result<bool, JwtError> {
    use p384::{
        ecdsa::{signature::Verifier, Signature, VerifyingKey},
        pkcs8::DecodePublicKey,
    };
    use sha2::{Sha384, Digest};
    
    let verifying_key = VerifyingKey::from_public_key_der(public_key_der)
        .map_err(|e| JwtError::invalid_key(&format!("Invalid EC public key: {}", e)))?;
    
    let signature = Signature::from_der(signature)
        .map_err(|_e| JwtError::invalid_signature())?;
    
    let mut hasher = Sha384::new();
    hasher.update(message.as_bytes());
    let hash = hasher.finalize();
    
    verifying_key.verify(&hash, &signature)
        .map(|_| true)
        .or_else(|_| Ok(false))
}

// Constant time comparison
#[inline]
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    
    let mut equal = true;
    for (x, y) in a.iter().zip(b.iter()) {
        equal &= x == y;
    }
    equal
}

// Validate standard JWT claims
fn validate_standard_claims(claims: &serde_json::Value) -> Result<(), JwtError> {
    if let Some(obj) = claims.as_object() {
        // Check expiration
        if let Some(exp) = obj.get("exp").and_then(|v| v.as_i64()) {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| JwtError::internal("System time error"))?
                .as_secs() as i64;
            
            if now > exp {
                return Err(JwtError::token_expired());
            }
        }
        
        // Check not before
        if let Some(nbf) = obj.get("nbf").and_then(|v| v.as_i64()) {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| JwtError::internal("System time error"))?
                .as_secs() as i64;
            
            if now < nbf {
                return Err(JwtError::token_not_yet_valid());
            }
        }
        
        // Validate exp > nbf if both present
        if let (Some(exp), Some(nbf)) = (
            obj.get("exp").and_then(|v| v.as_i64()),
            obj.get("nbf").and_then(|v| v.as_i64())
        ) {
            if exp <= nbf {
                return Err(JwtError::invalid_claims("exp must be after nbf"));
            }
        }
    }
    
    Ok(())
}

// Macro support for on_result! pattern
#[macro_export]
macro_rules! on_result {
    ($builder:expr, |$result:ident| { $($arms:tt)* }) => {
        $builder.on_result_sign(|$result| {
            match $result {
                $($arms)*
            }
        })
    };
}