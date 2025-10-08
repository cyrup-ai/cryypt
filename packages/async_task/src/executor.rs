//! Async executor patterns without blocking operations

use crate::{AsyncTask, TaskError, TaskResult};
use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::{RwLock, Semaphore};

/// Configuration for async executor
#[derive(Debug, Clone)]
pub struct ExecutorConfig {
    pub max_concurrent_tasks: usize,
    pub task_timeout: Option<std::time::Duration>,
    pub enable_metrics: bool,
}

impl Default for ExecutorConfig {
    fn default() -> Self {
        Self {
            max_concurrent_tasks: 100,
            task_timeout: None,
            enable_metrics: false,
        }
    }
}

/// Async executor that manages task execution without blocking
pub struct AsyncExecutor {
    config: ExecutorConfig,
    semaphore: Arc<Semaphore>,
    #[allow(dead_code)] // Library field - reserved for future task queuing functionality
    task_queue: Arc<RwLock<VecDeque<Box<dyn TaskExecution + Send + Sync>>>>,
    metrics: Arc<RwLock<ExecutorMetrics>>,
}

/// Metrics for executor performance
#[derive(Debug, Default)]
pub struct ExecutorMetrics {
    pub tasks_executed: u64,
    pub tasks_failed: u64,
    pub tasks_cancelled: u64,
    pub average_execution_time: std::time::Duration,
}

/// Trait for task execution (avoiding `async_trait`)
trait TaskExecution {
    #[allow(dead_code)] // Library method - reserved for future task execution functionality
    fn execute(&self) -> Pin<Box<dyn Future<Output = TaskResult<()>> + Send + '_>>;
}

impl AsyncExecutor {
    /// Create new async executor
    #[must_use]
    pub fn new(config: ExecutorConfig) -> Self {
        let semaphore = Arc::new(Semaphore::new(config.max_concurrent_tasks));

        Self {
            semaphore,
            config,
            task_queue: Arc::new(RwLock::new(VecDeque::new())),
            metrics: Arc::new(RwLock::new(ExecutorMetrics::default())),
        }
    }

    /// Execute a single task
    ///
    /// # Errors
    ///
    /// Returns `TaskError::Cancelled` if the task was cancelled or the executor is shutting down,
    /// `TaskError::Timeout` if the task exceeds the configured timeout, or any error from the task itself.
    pub async fn execute_task<T>(&self, task: AsyncTask<T>) -> TaskResult<T>
    where
        T: Send + 'static,
    {
        let _permit = self
            .semaphore
            .acquire()
            .await
            .map_err(|_| TaskError::Cancelled)?;

        let start_time = std::time::Instant::now();
        let result = if let Some(timeout) = self.config.task_timeout {
            task.execute_with_timeout(timeout).await
        } else {
            task.execute().await
        };

        if self.config.enable_metrics {
            self.update_metrics(&result, start_time.elapsed()).await;
        }

        result
    }

    /// Execute multiple tasks concurrently
    pub async fn execute_batch<T>(&self, tasks: Vec<AsyncTask<T>>) -> Vec<TaskResult<T>>
    where
        T: Send + 'static,
    {
        let futures = tasks.into_iter().map(|task| self.execute_task(task));
        futures::future::join_all(futures).await
    }

    /// Get current metrics
    pub async fn metrics(&self) -> ExecutorMetrics {
        self.metrics.read().await.clone()
    }

    async fn update_metrics<T>(&self, result: &TaskResult<T>, duration: std::time::Duration) {
        let mut metrics = self.metrics.write().await;

        match result {
            Ok(_) => metrics.tasks_executed += 1,
            Err(TaskError::Cancelled) => metrics.tasks_cancelled += 1,
            Err(_) => metrics.tasks_failed += 1,
        }

        // Simple moving average
        let total_tasks = metrics.tasks_executed + metrics.tasks_failed + metrics.tasks_cancelled;
        if total_tasks > 0 {
            let total_nanos = metrics.average_execution_time.as_nanos()
                * u128::from(total_tasks - 1)
                + duration.as_nanos();
            metrics.average_execution_time = std::time::Duration::from_nanos(
                u64::try_from(total_nanos / u128::from(total_tasks)).unwrap_or(u64::MAX),
            );
        }
    }
}

impl Clone for ExecutorMetrics {
    fn clone(&self) -> Self {
        Self {
            tasks_executed: self.tasks_executed,
            tasks_failed: self.tasks_failed,
            tasks_cancelled: self.tasks_cancelled,
            average_execution_time: self.average_execution_time,
        }
    }
}
