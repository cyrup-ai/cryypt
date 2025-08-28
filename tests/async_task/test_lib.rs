//! Basic task creation tests extracted from async_task/src/lib.rs

use async_task::AsyncTask;

#[tokio::test]
async fn basic_task_creation() {
    let task = AsyncTask::new(|| async { Ok(42) });
    let result = task.execute().await;
    assert!(result.is_ok());
}