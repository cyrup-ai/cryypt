//! Result types for store operations that support on_result pattern

use crate::{KeyError, Result};
use cryypt_common::NotResult;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::sync::oneshot;

/// Result type for exists operations
pub struct ExistsResult {
    receiver: oneshot::Receiver<Result<bool>>,
}

impl ExistsResult {
    pub(crate) fn new(receiver: oneshot::Receiver<Result<bool>>) -> Self {
        Self { receiver }
    }
    
    /// Add a result handler following README.md pattern
    pub fn on_result<F, T>(self, handler: F) -> ExistsResultWithHandler<F>
    where
        F: FnOnce(Result<bool>) -> T,
    {
        ExistsResultWithHandler {
            receiver: self.receiver,
            handler: Some(handler),
        }
    }
}

/// Exists result with user-defined error handler
pub struct ExistsResultWithHandler<F> {
    receiver: oneshot::Receiver<Result<bool>>,
    handler: Option<F>,
}

impl<F, T> Future for ExistsResultWithHandler<F>
where
    F: FnOnce(Result<bool>) -> T + Unpin,
    T: NotResult,
{
    type Output = T;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        match Pin::new(&mut this.receiver).poll(cx) {
            Poll::Ready(Ok(result)) => {
                if let Some(handler) = this.handler.take() {
                    Poll::Ready(handler(result))
                } else {
                    panic!("ExistsResultWithHandler polled after completion")
                }
            }
            Poll::Ready(Err(_)) => {
                if let Some(handler) = this.handler.take() {
                    Poll::Ready(handler(Err(KeyError::internal("Exists check task dropped"))))
                } else {
                    panic!("ExistsResultWithHandler polled after completion")
                }
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Result type for delete operations
pub struct DeleteResult {
    receiver: oneshot::Receiver<Result<()>>,
}

impl DeleteResult {
    pub(crate) fn new(receiver: oneshot::Receiver<Result<()>>) -> Self {
        Self { receiver }
    }
    
    /// Add a result handler following README.md pattern
    pub fn on_result<F, T>(self, handler: F) -> DeleteResultWithHandler<F>
    where
        F: FnOnce(Result<()>) -> T,
    {
        DeleteResultWithHandler {
            receiver: self.receiver,
            handler: Some(handler),
        }
    }
}

/// Delete result with user-defined error handler
pub struct DeleteResultWithHandler<F> {
    receiver: oneshot::Receiver<Result<()>>,
    handler: Option<F>,
}

impl<F, T> Future for DeleteResultWithHandler<F>
where
    F: FnOnce(Result<()>) -> T + Unpin,
    T: NotResult,
{
    type Output = T;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        match Pin::new(&mut this.receiver).poll(cx) {
            Poll::Ready(Ok(result)) => {
                if let Some(handler) = this.handler.take() {
                    Poll::Ready(handler(result))
                } else {
                    panic!("DeleteResultWithHandler polled after completion")
                }
            }
            Poll::Ready(Err(_)) => {
                if let Some(handler) = this.handler.take() {
                    Poll::Ready(handler(Err(KeyError::internal("Delete task dropped"))))
                } else {
                    panic!("DeleteResultWithHandler polled after completion")
                }
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Result type for store operations
pub struct StoreResult {
    receiver: oneshot::Receiver<Result<()>>,
}

impl StoreResult {
    pub(crate) fn new(receiver: oneshot::Receiver<Result<()>>) -> Self {
        Self { receiver }
    }
    
    /// Add a result handler following README.md pattern
    pub fn on_result<F, T>(self, handler: F) -> StoreResultWithHandler<F>
    where
        F: FnOnce(Result<()>) -> T,
    {
        StoreResultWithHandler {
            receiver: self.receiver,
            handler: Some(handler),
        }
    }
}

/// Store result with user-defined error handler
pub struct StoreResultWithHandler<F> {
    receiver: oneshot::Receiver<Result<()>>,
    handler: Option<F>,
}

impl<F, T> Future for StoreResultWithHandler<F>
where
    F: FnOnce(Result<()>) -> T + Unpin,
    T: NotResult,
{
    type Output = T;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        match Pin::new(&mut this.receiver).poll(cx) {
            Poll::Ready(Ok(result)) => {
                if let Some(handler) = this.handler.take() {
                    Poll::Ready(handler(result))
                } else {
                    panic!("StoreResultWithHandler polled after completion")
                }
            }
            Poll::Ready(Err(_)) => {
                if let Some(handler) = this.handler.take() {
                    Poll::Ready(handler(Err(KeyError::internal("Store task dropped"))))
                } else {
                    panic!("StoreResultWithHandler polled after completion")
                }
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Result type for retrieve operations  
pub struct RetrieveResult {
    receiver: oneshot::Receiver<Result<Vec<u8>>>,
}

impl RetrieveResult {
    pub(crate) fn new(receiver: oneshot::Receiver<Result<Vec<u8>>>) -> Self {
        Self { receiver }
    }
    
    /// Add a result handler following README.md pattern
    pub fn on_result<F, T>(self, handler: F) -> RetrieveResultWithHandler<F>
    where
        F: FnOnce(Result<Vec<u8>>) -> T,
    {
        RetrieveResultWithHandler {
            receiver: self.receiver,
            handler: Some(handler),
        }
    }
}

/// Retrieve result with user-defined error handler
pub struct RetrieveResultWithHandler<F> {
    receiver: oneshot::Receiver<Result<Vec<u8>>>,
    handler: Option<F>,
}

impl<F, T> Future for RetrieveResultWithHandler<F>
where
    F: FnOnce(Result<Vec<u8>>) -> T + Unpin,
    T: NotResult,
{
    type Output = T;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        match Pin::new(&mut this.receiver).poll(cx) {
            Poll::Ready(Ok(result)) => {
                if let Some(handler) = this.handler.take() {
                    Poll::Ready(handler(result))
                } else {
                    panic!("RetrieveResultWithHandler polled after completion")
                }
            }
            Poll::Ready(Err(_)) => {
                if let Some(handler) = this.handler.take() {
                    Poll::Ready(handler(Err(KeyError::internal("Retrieve task dropped"))))
                } else {
                    panic!("RetrieveResultWithHandler polled after completion")
                }
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Result type for list operations
pub struct ListResult {
    receiver: oneshot::Receiver<Result<Vec<String>>>,
}

impl ListResult {
    pub(crate) fn new(receiver: oneshot::Receiver<Result<Vec<String>>>) -> Self {
        Self { receiver }
    }
    
    /// Add a result handler following README.md pattern
    pub fn on_result<F, T>(self, handler: F) -> ListResultWithHandler<F>
    where
        F: FnOnce(Result<Vec<String>>) -> T,
    {
        ListResultWithHandler {
            receiver: self.receiver,
            handler: Some(handler),
        }
    }
}

/// List result with user-defined error handler
pub struct ListResultWithHandler<F> {
    receiver: oneshot::Receiver<Result<Vec<String>>>,
    handler: Option<F>,
}

impl<F, T> Future for ListResultWithHandler<F>
where
    F: FnOnce(Result<Vec<String>>) -> T + Unpin,
    T: NotResult,
{
    type Output = T;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        match Pin::new(&mut this.receiver).poll(cx) {
            Poll::Ready(Ok(result)) => {
                if let Some(handler) = this.handler.take() {
                    Poll::Ready(handler(result))
                } else {
                    panic!("ListResultWithHandler polled after completion")
                }
            }
            Poll::Ready(Err(_)) => {
                if let Some(handler) = this.handler.take() {
                    Poll::Ready(handler(Err(KeyError::internal("List task dropped"))))
                } else {
                    panic!("ListResultWithHandler polled after completion")
                }
            }
            Poll::Pending => Poll::Pending,
        }
    }
}