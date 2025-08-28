//! Task tests extracted from async_task/src/task.rs

use async_task::{AsyncTask, TaskError};
use std::time::Duration;

#[tokio::test]
async fn test_basic_task() {
    let task = AsyncTask::new(|| async { Ok(42) });
    let result = task.execute().await.expect("Basic task execution should succeed");
    assert_eq!(result, 42);
}

#[tokio::test]
async fn test_task_with_timeout() {
    let task = AsyncTask::new(|| async {
        tokio::time::sleep(Duration::from_millis(100)).await;
        Ok(42)
    });
    
    let result = task.execute_with_timeout(Duration::from_millis(50)).await;
    assert!(matches!(result, Err(TaskError::Timeout)));
}

#[tokio::test]
async fn test_task_cancellation() {
    let task = AsyncTask::new(|| async {
        tokio::time::sleep(Duration::from_millis(100)).await;
        Ok(42)
    });
    
    let (cancel_tx, cancel_rx) = tokio::sync::oneshot::channel();
    
    let task_handle = tokio::spawn(async move {
        task.execute_with_cancellation(cancel_rx).await
    });
    
    // Cancel immediately
    cancel_tx.send(()).expect("Cancellation signal should be sent successfully");
    
    let result = task_handle.await.expect("Task handle should complete without panicking");
    assert!(matches!(result, Err(TaskError::Cancelled)));
}