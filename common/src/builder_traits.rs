//! Common builder traits for consistent on_result/on_chunk/on_error patterns

use crate::NotResult;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

/// Standard result handler type that transforms Result<T> -> U where U: NotResult
pub type ResultHandler<T, U> = Box<dyn FnOnce(Result<T, Box<dyn std::error::Error + Send + Sync>>) -> U + Send>;

/// Standard chunk handler type for streaming operations
pub type ChunkHandler<T> = Box<dyn Fn(Result<T, Box<dyn std::error::Error + Send + Sync>>) -> Option<T> + Send + Sync>;

/// Standard error handler type for error processing
pub type ErrorHandler<E> = Box<dyn Fn(E) -> E + Send + Sync>;

/// Generic async result with handler support
pub struct AsyncResultWithHandler<T, U, F> {
    receiver: tokio::sync::oneshot::Receiver<Result<T, Box<dyn std::error::Error + Send + Sync>>>,
    handler: Option<F>,
    _phantom: std::marker::PhantomData<U>,
}

impl<T, U, F> AsyncResultWithHandler<T, U, F> {
    pub fn new(
        receiver: tokio::sync::oneshot::Receiver<Result<T, Box<dyn std::error::Error + Send + Sync>>>,
        handler: F,
    ) -> Self {
        Self {
            receiver,
            handler: Some(handler),
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<T, U, F> Future for AsyncResultWithHandler<T, U, F>
where
    F: FnOnce(Result<T, Box<dyn std::error::Error + Send + Sync>>) -> U + Unpin,
    U: NotResult + Unpin,
    T: Send + 'static,
{
    type Output = U;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        match Pin::new(&mut this.receiver).poll(cx) {
            Poll::Ready(Ok(result)) => {
                if let Some(handler) = this.handler.take() {
                    Poll::Ready(handler(result))
                } else {
                    panic!("AsyncResultWithHandler polled after completion")
                }
            }
            Poll::Ready(Err(_)) => {
                if let Some(handler) = this.handler.take() {
                    let error: Box<dyn std::error::Error + Send + Sync> = 
                        Box::new(std::io::Error::new(std::io::ErrorKind::Other, "Task dropped"));
                    Poll::Ready(handler(Err(error)))
                } else {
                    panic!("AsyncResultWithHandler polled after completion")
                }
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Trait for builders that support the standard on_result pattern
pub trait OnResultBuilder<T> {
    type WithHandler<U, F>: Future<Output = U>
    where
        F: FnOnce(Result<T, Box<dyn std::error::Error + Send + Sync>>) -> U + Send + 'static,
        U: NotResult + Send + 'static;

    /// Add result handler that transforms Result<T> -> U
    fn on_result<F, U>(self, handler: F) -> Self::WithHandler<U, F>
    where
        F: FnOnce(Result<T, Box<dyn std::error::Error + Send + Sync>>) -> U + Send + 'static,
        U: NotResult + Send + 'static;
}

/// Trait for builders that support the standard on_chunk pattern
pub trait OnChunkBuilder<T> {
    type Stream: futures::Stream<Item = T>;

    /// Add chunk handler for streaming operations
    fn on_chunk<F>(self, handler: F) -> Self::Stream
    where
        F: Fn(Result<T, Box<dyn std::error::Error + Send + Sync>>) -> Option<T> + Send + Sync + 'static;
}

/// Trait for builders that support the standard on_error pattern
pub trait OnErrorBuilder<E> {
    /// Add error handler for error processing
    fn on_error<F>(self, handler: F) -> Self
    where
        F: Fn(E) -> E + Send + Sync + 'static;
}

/// Macro to implement standard handler patterns for any builder
#[macro_export]
macro_rules! impl_standard_handlers {
    ($builder:ty, $result_type:ty, $error_type:ty) => {
        impl $builder {
            /// Add on_result handler - standard pattern
            pub fn on_result<F, U>(self, handler: F) -> cryypt_common::builder_traits::AsyncResultWithHandler<$result_type, U, F>
            where
                F: FnOnce(Result<$result_type, Box<dyn std::error::Error + Send + Sync>>) -> U + Send + 'static,
                U: cryypt_common::NotResult + Send + 'static,
            {
                let (tx, rx) = tokio::sync::oneshot::channel();
                // Implementation would spawn the actual work here
                cryypt_common::builder_traits::AsyncResultWithHandler::new(rx, handler)
            }

            /// Add on_chunk handler - standard pattern
            pub fn on_chunk<F>(mut self, handler: F) -> Self
            where
                F: Fn(Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>>) -> Option<Vec<u8>> + Send + Sync + 'static,
            {
                // Implementation would store the handler
                self
            }

            /// Add on_error handler - standard pattern  
            pub fn on_error<F>(mut self, handler: F) -> Self
            where
                F: Fn($error_type) -> $error_type + Send + Sync + 'static,
            {
                // Implementation would store the handler
                self
            }
        }
    };
}