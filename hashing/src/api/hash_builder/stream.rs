//! Hash streaming operations

use super::{sha256::Sha256Hasher, sha3::{Sha3_256Hasher, Sha3_384Hasher, Sha3_512Hasher}, blake2b::Blake2bHasher};
use crate::Result;
use std::future::Future;
use std::pin::Pin;
use tokio::sync::mpsc;
use tokio_stream::Stream;

// Hash algorithm enum for streaming
#[derive(Clone)]
pub enum HashAlgorithm {
    Sha256,
    Sha3_256,
    Sha3_384,
    Sha3_512,
    Blake2b(u8),
}

/// Stream of hash chunks
pub struct HashStream {
    receiver: mpsc::Receiver<Result<Vec<u8>>>,
    handler: Option<Box<dyn Fn(Result<Vec<u8>>) -> Option<Vec<u8>> + Send>>,
}

impl HashStream {
    /// Create a new hash stream
    pub fn new<S>(
        stream: S,
        algorithm: HashAlgorithm,
        handler: Option<Box<dyn Fn(Result<Vec<u8>>) -> Option<Vec<u8>> + Send + Sync>>,
    ) -> Self
    where
        S: Stream<Item = Vec<u8>> + Send + 'static,
    {
        let (sender, receiver) = mpsc::channel(100);
        
        // Spawn task to process stream
        tokio::spawn(async move {
            use tokio_stream::StreamExt;
            let mut stream = Box::pin(stream);
            let mut hasher = create_hasher(&algorithm);
            
            while let Some(chunk) = stream.next().await {
                // Update hash with chunk
                hasher.update(&chunk);
                
                // Send intermediate result
                let intermediate = hasher.clone_finalize();
                let _ = sender.send(Ok(intermediate)).await;
            }
            
            // Send final hash
            let final_hash = hasher.finalize();
            let _ = sender.send(Ok(final_hash)).await;
        });
        
        HashStream {
            receiver,
            handler: handler.map(|h| Box::new(h) as Box<dyn Fn(Result<Vec<u8>>) -> Option<Vec<u8>> + Send>),
        }
    }
    
    /// Apply on_chunk! handler to the stream
    pub fn on_chunk<F>(mut self, handler: F) -> Self
    where
        F: Fn(Result<Vec<u8>>) -> Option<Vec<u8>> + Send + 'static,
    {
        self.handler = Some(Box::new(handler));
        self
    }
}

impl Stream for HashStream {
    type Item = Vec<u8>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<Option<Self::Item>> {
        
        match self.receiver.poll_recv(cx) {
            std::task::Poll::Ready(Some(result)) => {
                if let Some(handler) = &self.handler {
                    std::task::Poll::Ready(handler(result))
                } else {
                    match result {
                        Ok(chunk) => std::task::Poll::Ready(Some(chunk)),
                        Err(_) => std::task::Poll::Ready(None),
                    }
                }
            }
            std::task::Poll::Ready(None) => std::task::Poll::Ready(None),
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}

// Implement standard async iteration
impl HashStream {
    /// Get the next chunk from the stream
    pub async fn next(&mut self) -> Option<Vec<u8>> {
        use tokio_stream::StreamExt;
        StreamExt::next(self).await
    }
}

// Helper to create hasher based on algorithm
fn create_hasher(algorithm: &HashAlgorithm) -> Box<dyn DynHasher> {
    match algorithm {
        HashAlgorithm::Sha256 => Box::new(Sha256Hasher::new()),
        HashAlgorithm::Sha3_256 => Box::new(Sha3_256Hasher::new()),
        HashAlgorithm::Sha3_384 => Box::new(Sha3_384Hasher::new()),
        HashAlgorithm::Sha3_512 => Box::new(Sha3_512Hasher::new()),
        HashAlgorithm::Blake2b(size) => Box::new(Blake2bHasher::new(*size)),
    }
}

// Trait for async hash results
pub trait AsyncHashResult: Future<Output = Result<Vec<u8>>> + Send {}
impl<T> AsyncHashResult for T where T: Future<Output = Result<Vec<u8>>> + Send {}


// Dynamic hasher trait for streaming
pub(super) trait DynHasher: Send {
    fn update(&mut self, data: &[u8]);
    fn clone_finalize(&self) -> Vec<u8>;
    fn finalize(self: Box<Self>) -> Vec<u8>;
}