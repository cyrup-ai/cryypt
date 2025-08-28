//! Tests for async executor patterns extracted from async_task/src/executor.rs
//!
//! Tests the ExecutorConfig, AsyncExecutor functionality with proper async coordination.

use cryypt_async_task::{AsyncExecutor, AsyncTask, ExecutorConfig};
use std::time::Duration;

#[tokio::test]
async fn test_executor_basic() {
    let config = ExecutorConfig::default();
    let executor = AsyncExecutor::new(config);
    
    let task = AsyncTask::new(|| async { Ok(42) });
    let result = executor.execute_task(task).await.expect("Task execution should succeed");
    assert_eq!(result, 42);
}

#[tokio::test]
async fn test_executor_batch() {
    let config = ExecutorConfig::default();
    let executor = AsyncExecutor::new(config);
    
    let tasks = (0..5).map(|i| AsyncTask::new(move || async move { Ok(i) })).collect();
    let results = executor.execute_batch(tasks).await;
    
    assert_eq!(results.len(), 5);
    for (i, result) in results.into_iter().enumerate() {
        assert_eq!(result.expect("Individual task should succeed"), i);
    }
}