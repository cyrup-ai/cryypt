//! Shared builder components for composition across all cryypt modules
//!
//! These components can be composed into any builder to provide consistent behavior

use std::marker::PhantomData;
use tokio::sync::oneshot;

/// Handler component that can be composed into any builder
pub struct Handler<F, T> {
    pub handler: F,
    pub _phantom: PhantomData<T>,
}

impl<F, T> Handler<F, T> {
    pub fn new(handler: F) -> Self {
        Self {
            handler,
            _phantom: PhantomData,
        }
    }
}

/// Key storage component that can be composed into any builder
pub struct KeyStore {
    pub key: Vec<u8>,
}

impl KeyStore {
    pub fn new(key: Vec<u8>) -> Self {
        Self { key }
    }
}

/// Async executor component that handles channel-based async operations
pub struct AsyncExecutor;

impl AsyncExecutor {
    pub fn execute<F, R>(task: F) -> AsyncResult<R>
    where
        F: FnOnce() -> R + Send + 'static,
        R: Send + 'static,
    {
        let (tx, rx) = oneshot::channel();
        
        tokio::spawn(async move {
            let result = task();
            let _ = tx.send(result);
        });
        
        AsyncResult::new(rx)
    }
}

/// Generic async result that wraps oneshot channel
pub struct AsyncResult<T> {
    receiver: oneshot::Receiver<T>,
}

impl<T> AsyncResult<T> {
    pub fn new(receiver: oneshot::Receiver<T>) -> Self {
        Self { receiver }
    }
}

impl<T> std::future::Future for AsyncResult<T> {
    type Output = Result<T, Box<dyn std::error::Error + Send + Sync>>;

    fn poll(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<Self::Output> {
        use std::pin::Pin;
        match Pin::new(&mut self.receiver).poll(cx) {
            std::task::Poll::Ready(Ok(result)) => std::task::Poll::Ready(Ok(result)),
            std::task::Poll::Ready(Err(_)) => std::task::Poll::Ready(Err("Channel closed".into())),
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}