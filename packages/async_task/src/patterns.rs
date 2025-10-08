//! Common async patterns without `async_trait`

use crate::TaskError;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot, RwLock};

type RequestReceiver<Req, Resp> =
    Arc<RwLock<Option<mpsc::UnboundedReceiver<(Req, oneshot::Sender<Resp>)>>>>;

/// Async pattern builder for common coordination patterns
pub struct PatternBuilder;

impl PatternBuilder {
    /// Create a request-response pattern
    #[must_use]
    pub fn request_response<Req, Resp>() -> RequestResponsePattern<Req, Resp>
    where
        Req: Send + 'static,
        Resp: Send + 'static,
    {
        RequestResponsePattern::new()
    }

    /// Create a producer-consumer pattern
    #[must_use]
    pub fn producer_consumer<T>(buffer_size: usize) -> ProducerConsumerPattern<T>
    where
        T: Send + 'static,
    {
        ProducerConsumerPattern::new(buffer_size)
    }

    /// Create a fan-out pattern
    #[must_use]
    pub fn fan_out<T>() -> FanOutPattern<T>
    where
        T: Clone + Send + 'static,
    {
        FanOutPattern::new()
    }
}

/// Request-response async pattern
pub struct RequestResponsePattern<Req, Resp> {
    sender: mpsc::UnboundedSender<(Req, oneshot::Sender<Resp>)>,
    receiver: RequestReceiver<Req, Resp>,
}

impl<Req, Resp> RequestResponsePattern<Req, Resp>
where
    Req: Send + 'static,
    Resp: Send + 'static,
{
    fn new() -> Self {
        let (sender, receiver) = mpsc::unbounded_channel();
        Self {
            sender,
            receiver: Arc::new(RwLock::new(Some(receiver))),
        }
    }

    /// Send a request and wait for response
    ///
    /// # Errors
    ///
    /// Returns `TaskError::Channel` if the request channel is closed or if the response
    /// channel is closed before receiving a response.
    pub async fn request(&self, req: Req) -> Result<Resp, TaskError> {
        let (resp_tx, resp_rx) = oneshot::channel();

        self.sender
            .send((req, resp_tx))
            .map_err(|_| TaskError::Channel("Request channel closed".to_string()))?;

        resp_rx
            .await
            .map_err(|_| TaskError::Channel("Response channel closed".to_string()))
    }

    /// Start handling requests with a processor function
    ///
    /// # Errors
    ///
    /// Returns `TaskError::Channel` if the handler has already been started (receiver
    /// has already been taken).
    pub async fn start_handler<F, Fut>(&self, processor: F) -> Result<(), TaskError>
    where
        F: Fn(Req) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Resp> + Send + 'static,
    {
        let mut receiver_guard = self.receiver.write().await;
        let receiver = receiver_guard
            .take()
            .ok_or_else(|| TaskError::Channel("Handler already started".to_string()))?;
        drop(receiver_guard);

        tokio::spawn(async move {
            let mut receiver = receiver;
            while let Some((req, resp_tx)) = receiver.recv().await {
                let response = processor(req).await;
                let _ = resp_tx.send(response);
            }
        });

        Ok(())
    }
}

/// Producer-consumer async pattern
pub struct ProducerConsumerPattern<T> {
    sender: mpsc::Sender<T>,
    receiver: Arc<RwLock<Option<mpsc::Receiver<T>>>>,
}

impl<T> ProducerConsumerPattern<T>
where
    T: Send + 'static,
{
    fn new(buffer_size: usize) -> Self {
        let (sender, receiver) = mpsc::channel(buffer_size);
        Self {
            sender,
            receiver: Arc::new(RwLock::new(Some(receiver))),
        }
    }

    /// Produce an item
    ///
    /// # Errors
    ///
    /// Returns `TaskError::Channel` if the producer channel is closed.
    pub async fn produce(&self, item: T) -> Result<(), TaskError> {
        self.sender
            .send(item)
            .await
            .map_err(|_| TaskError::Channel("Producer channel closed".to_string()))
    }

    /// Start consuming with a processor function
    ///
    /// # Errors
    ///
    /// Returns `TaskError::Channel` if the consumer has already been started (receiver
    /// has already been taken).
    pub async fn start_consumer<F, Fut>(&self, processor: F) -> Result<(), TaskError>
    where
        F: Fn(T) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let mut receiver_guard = self.receiver.write().await;
        let receiver = receiver_guard
            .take()
            .ok_or_else(|| TaskError::Channel("Consumer already started".to_string()))?;
        drop(receiver_guard);

        tokio::spawn(async move {
            let mut receiver = receiver;
            while let Some(item) = receiver.recv().await {
                processor(item).await;
            }
        });

        Ok(())
    }
}

/// Fan-out async pattern for broadcasting
pub struct FanOutPattern<T> {
    senders: Arc<RwLock<Vec<mpsc::UnboundedSender<T>>>>,
}

impl<T> FanOutPattern<T>
where
    T: Clone + Send + 'static,
{
    fn new() -> Self {
        Self {
            senders: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Add a new subscriber
    pub async fn subscribe(&self) -> mpsc::UnboundedReceiver<T> {
        let (sender, receiver) = mpsc::unbounded_channel();
        let mut senders = self.senders.write().await;
        senders.push(sender);
        receiver
    }

    /// Broadcast to all subscribers
    ///
    /// # Errors
    ///
    /// This method does not currently return errors, but the signature allows for future
    /// error handling if needed. Always returns `Ok(())`.
    pub async fn broadcast(&self, item: T) -> Result<(), TaskError> {
        let senders = self.senders.read().await;
        let mut failed_indices = Vec::new();

        for (i, sender) in senders.iter().enumerate() {
            if sender.send(item.clone()).is_err() {
                failed_indices.push(i);
            }
        }

        // Clean up failed senders
        if !failed_indices.is_empty() {
            drop(senders);
            let mut senders = self.senders.write().await;
            for &i in failed_indices.iter().rev() {
                senders.remove(i);
            }
        }

        Ok(())
    }
}

/// Base trait for async patterns (avoiding `async_trait`)
pub trait AsyncPattern {
    type Output;

    fn execute(&self) -> Pin<Box<dyn Future<Output = Self::Output> + Send + '_>>;
}
