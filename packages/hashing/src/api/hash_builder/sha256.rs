//! SHA-256 hash implementation

use super::super::{
    hash::Sha256Hash,
    HasSalt, NoData, NoSalt,
};
use super::{HashBuilder, HashStream, HashAlgorithm};
use super::stream::DynHasher;
use crate::{HashResult, Result};
use tokio_stream::Stream;

// SHA-256 compute methods without key
impl<P> HashBuilder<Sha256Hash, NoData, NoSalt, P> {
    /// Compute hash of the provided data
    /// Returns unwrapped Vec<u8> with default error handling (empty Vec on error)
    pub async fn compute<T: Into<Vec<u8>>>(self, data: T) -> Vec<u8> {
        let data = data.into();
        let result = sha256_hash(data, None, 1).await.map(HashResult::from);
        
        if let Some(handler) = self.result_handler {
            // User provided handler: give them Result<HashResult>, get back Vec<u8>
            (*handler)(result)
        } else {
            // Default unwrapping: Ok(hash_result) => hash_result.to_vec(), Err(_) => Vec::new()
            match result {
                Ok(hash_result) => hash_result.to_vec(),
                Err(_) => Vec::new(),
            }
        }
    }
    
    /// Compute hash from a stream of data
    pub fn compute_stream<S: Stream<Item = Vec<u8>> + Send + 'static>(
        self, 
        stream: S
    ) -> HashStream {
        HashStream::new(stream, HashAlgorithm::Sha256, self.chunk_handler)
    }
}

// SHA-256 compute methods with key (HMAC)
impl<P> HashBuilder<Sha256Hash, NoData, HasSalt, P> {
    /// Compute HMAC of the provided data
    /// Returns unwrapped Vec<u8> with default error handling (empty Vec on error)
    pub async fn compute<T: Into<Vec<u8>>>(self, data: T) -> Vec<u8> {
        let data = data.into();
        let result = sha256_hmac(data, self.salt.0).await.map(HashResult::from);
        
        if let Some(handler) = self.result_handler {
            // User provided handler: give them Result<HashResult>, get back Vec<u8>
            (*handler)(result)
        } else {
            // Default unwrapping: Ok(hash_result) => hash_result.to_vec(), Err(_) => Vec::new()
            match result {
                Ok(hash_result) => hash_result.to_vec(),
                Err(_) => Vec::new(),
            }
        }
    }
    
    /// Compute HMAC from a stream of data
    pub fn compute_stream<S: Stream<Item = Vec<u8>> + Send + 'static>(
        self, 
        stream: S
    ) -> HashStream {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        use tokio::sync::mpsc;
        
        let key = self.salt.0.clone();
        let (sender, receiver) = mpsc::channel(100);
        let chunk_handler = self.chunk_handler;
        
        tokio::spawn(async move {
            use tokio_stream::StreamExt;
            use crate::error::{HashError, Result};
            let mut stream = Box::pin(stream);
            let mut mac = Hmac::<Sha256>::new_from_slice(&key)
                .map_err(|e| HashError::MacInitialization(format!("Failed to initialize SHA256 HMAC: {e}")))?;
            
            while let Some(chunk) = stream.next().await {
                mac.update(&chunk);
                // Send intermediate HMAC for progressive verification
                let intermediate = mac.clone().finalize().into_bytes().to_vec();
                let _ = sender.send(Ok(intermediate)).await;
            }
            
            // Final HMAC
            let final_mac = mac.finalize().into_bytes().to_vec();
            let _ = sender.send(Ok(final_mac)).await;
        });
        
        HashStream {
            receiver,
            handler: chunk_handler.map(|h| Box::new(h) as Box<dyn Fn(Result<Vec<u8>>) -> Option<Vec<u8>> + Send>),
        }
    }
}

// SHA-256 hasher
pub(super) struct Sha256Hasher(sha2::Sha256);

impl Sha256Hasher {
    pub(super) fn new() -> Self {
        use sha2::{Digest, Sha256};
        Self(Sha256::new())
    }
}

impl DynHasher for Sha256Hasher {
    fn update(&mut self, data: &[u8]) {
        use sha2::Digest;
        self.0.update(data);
    }
    
    fn clone_finalize(&self) -> Vec<u8> {
        use sha2::Digest;
        self.0.clone().finalize().to_vec()
    }
    
    fn finalize(self: Box<Self>) -> Vec<u8> {
        use sha2::Digest;
        self.0.finalize().to_vec()
    }
}

// SHA-256 hash function
pub(super) async fn sha256_hash(data: Vec<u8>, salt: Option<Vec<u8>>, passes: u32) -> Result<Vec<u8>> {
    use sha2::{Digest, Sha256};

    let mut input = data;
    if let Some(salt) = salt {
        input.extend_from_slice(&salt);
    }

    let mut result = input.clone();
    for _ in 0..passes {
        let mut hasher = Sha256::new();
        hasher.update(&result);
        result = hasher.finalize().to_vec();
    }

    Ok(result)
}

// SHA-256 HMAC function
pub(super) async fn sha256_hmac(data: Vec<u8>, key: Vec<u8>) -> Result<Vec<u8>> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    
    type HmacSha256 = Hmac<Sha256>;
    
    let mut mac = HmacSha256::new_from_slice(&key)
        .map_err(|e| crate::HashError::internal(format!("HMAC key error: {e}")))?;
    mac.update(&data);
    Ok(mac.finalize().into_bytes().to_vec())
}