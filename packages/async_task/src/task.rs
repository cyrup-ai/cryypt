//! Async task coordination without `async_trait`

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

/// Error types for async task operations
#[derive(Debug, thiserror::Error)]
pub enum TaskError {
    #[error("Task execution failed: {0}")]
    ExecutionFailed(String),
    #[error("Task was cancelled")]
    Cancelled,
    #[error("Channel error: {0}")]
    Channel(String),
    #[error("Timeout error")]
    Timeout,
}

/// Result type for async tasks
pub type TaskResult<T> = Result<T, TaskError>;
pub type TaskFn<T> =
    Arc<dyn Fn() -> Pin<Box<dyn Future<Output = TaskResult<T>> + Send>> + Send + Sync>;

/// Async task that can be executed without blocking
pub struct AsyncTask<T> {
    inner: TaskFn<T>,
}

impl<T> AsyncTask<T>
where
    T: Send + 'static,
{
    /// Create a new async task from a closure that returns a future
    pub fn new<F, Fut>(f: F) -> Self
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = TaskResult<T>> + Send + 'static,
    {
        Self {
            inner: Arc::new(move || Box::pin(f())),
        }
    }

    /// Execute the task asynchronously
    ///
    /// # Errors
    ///
    /// Returns `TaskError::ExecutionFailed` if the task execution fails,
    /// `TaskError::Cancelled` if the task was cancelled, or other task-specific errors.
    pub async fn execute(&self) -> TaskResult<T> {
        (self.inner)().await
    }

    /// Execute with timeout
    ///
    /// # Errors
    ///
    /// Returns `TaskError::Timeout` if the task exceeds the timeout duration,
    /// or any error returned by the underlying task execution.
    pub async fn execute_with_timeout(&self, duration: std::time::Duration) -> TaskResult<T> {
        match tokio::time::timeout(duration, self.execute()).await {
            Ok(result) => result,
            Err(_) => Err(TaskError::Timeout),
        }
    }

    /// Execute with cancellation support
    ///
    /// # Errors
    ///
    /// Returns `TaskError::Cancelled` if the task was cancelled via the provided receiver,
    /// or any error returned by the underlying task execution.
    pub async fn execute_with_cancellation(
        &self,
        mut cancel_rx: tokio::sync::oneshot::Receiver<()>,
    ) -> TaskResult<T> {
        tokio::select! {
            result = self.execute() => result,
            _ = &mut cancel_rx => Err(TaskError::Cancelled),
        }
    }
}

/// Builder for creating async tasks with configuration
pub struct AsyncTaskBuilder<T> {
    timeout: Option<std::time::Duration>,
    cancellable: bool,
    _phantom: std::marker::PhantomData<T>,
}

impl<T> Default for AsyncTaskBuilder<T> {
    fn default() -> Self {
        Self {
            timeout: None,
            cancellable: false,
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<T> AsyncTaskBuilder<T>
where
    T: Send + 'static,
{
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn with_timeout(mut self, duration: std::time::Duration) -> Self {
        self.timeout = Some(duration);
        self
    }

    #[must_use]
    pub fn cancellable(mut self) -> Self {
        self.cancellable = true;
        self
    }

    pub fn build<F, Fut>(self, f: F) -> AsyncTask<T>
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = TaskResult<T>> + Send + 'static,
    {
        AsyncTask::new(f)
    }
}
