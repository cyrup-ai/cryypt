//! Tests for `store_results` Future error handling - ensuring no panics occur

use cryypt_key::store_results::*;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};
use tokio::sync::oneshot;

struct TestWaker;

impl std::task::Wake for TestWaker {
    fn wake(self: Arc<Self>) {}
}

fn create_test_waker() -> Waker {
    Arc::new(TestWaker).into()
}

#[tokio::test]
async fn test_exists_result_multiple_polls_after_completion() {
    let (tx, rx) = oneshot::channel();
    let handler = |result: Result<bool, cryypt_key::KeyError>| match result {
        Ok(exists) => format!("exists: {exists}"),
        Err(e) => format!("error: {e}"),
    };

    let mut future = ExistsResultWithHandler::new(rx, handler);

    // Send result to complete the future
    tx.send(Ok(true)).unwrap();

    // First poll should complete successfully
    let waker = create_test_waker();
    let mut cx = Context::from_waker(&waker);
    let result = Pin::new(&mut future).poll(&mut cx);
    assert!(matches!(result, Poll::Ready(_)));

    // Second poll should return Pending (not panic)
    let result = Pin::new(&mut future).poll(&mut cx);
    assert!(matches!(result, Poll::Pending));

    // Third poll should also return Pending (not panic)
    let result = Pin::new(&mut future).poll(&mut cx);
    assert!(matches!(result, Poll::Pending));
}

#[tokio::test]
async fn test_delete_result_multiple_polls_after_completion() {
    let (tx, rx) = oneshot::channel();
    let handler = |result: Result<(), cryypt_key::KeyError>| match result {
        Ok(()) => "deleted: success".to_string(),
        Err(e) => format!("error: {e}"),
    };

    let mut future = DeleteResultWithHandler::new(rx, handler);

    // Send result to complete the future
    tx.send(Ok(())).unwrap();

    // First poll should complete successfully
    let waker = create_test_waker();
    let mut cx = Context::from_waker(&waker);
    let result = Pin::new(&mut future).poll(&mut cx);
    assert!(matches!(result, Poll::Ready(_)));

    // Subsequent polls should return Pending (not panic)
    let result = Pin::new(&mut future).poll(&mut cx);
    assert!(matches!(result, Poll::Pending));
}

#[tokio::test]
async fn test_store_result_multiple_polls_after_completion() {
    let (tx, rx) = oneshot::channel();
    let handler = |result: Result<(), cryypt_key::KeyError>| match result {
        Ok(()) => "stored: success".to_string(),
        Err(e) => format!("error: {e}"),
    };

    let mut future = StoreResultWithHandler::new(rx, handler);

    // Send result to complete the future
    tx.send(Ok(())).unwrap();

    // First poll should complete successfully
    let waker = create_test_waker();
    let mut cx = Context::from_waker(&waker);
    let result = Pin::new(&mut future).poll(&mut cx);
    assert!(matches!(result, Poll::Ready(_)));

    // Subsequent polls should return Pending (not panic)
    let result = Pin::new(&mut future).poll(&mut cx);
    assert!(matches!(result, Poll::Pending));
}

#[tokio::test]
async fn test_retrieve_result_multiple_polls_after_completion() {
    let (tx, rx) = oneshot::channel();
    let handler = |result: Result<Vec<u8>, cryypt_key::KeyError>| match result {
        Ok(data) => format!("retrieved: {} bytes", data.len()),
        Err(e) => format!("error: {e}"),
    };

    let mut future = RetrieveResultWithHandler::new(rx, handler);

    // Send result to complete the future
    tx.send(Ok(vec![1, 2, 3, 4])).unwrap();

    // First poll should complete successfully
    let waker = create_test_waker();
    let mut cx = Context::from_waker(&waker);
    let result = Pin::new(&mut future).poll(&mut cx);
    assert!(matches!(result, Poll::Ready(_)));

    // Subsequent polls should return Pending (not panic)
    let result = Pin::new(&mut future).poll(&mut cx);
    assert!(matches!(result, Poll::Pending));
}

#[tokio::test]
async fn test_list_result_multiple_polls_after_completion() {
    let (tx, rx) = oneshot::channel();
    let handler = |result: Result<Vec<String>, cryypt_key::KeyError>| match result {
        Ok(keys) => format!("listed: {} items", keys.len()),
        Err(e) => format!("error: {e}"),
    };

    let mut future = ListResultWithHandler::new(rx, handler);

    // Send result to complete the future
    tx.send(Ok(vec!["key1".to_string(), "key2".to_string()]))
        .unwrap();

    // First poll should complete successfully
    let waker = create_test_waker();
    let mut cx = Context::from_waker(&waker);
    let result = Pin::new(&mut future).poll(&mut cx);
    assert!(matches!(result, Poll::Ready(_)));

    // Subsequent polls should return Pending (not panic)
    let result = Pin::new(&mut future).poll(&mut cx);
    assert!(matches!(result, Poll::Pending));
}

#[tokio::test]
async fn test_sender_dropped_before_completion() {
    let (tx, rx) = oneshot::channel();
    let handler = |result: Result<bool, cryypt_key::KeyError>| match result {
        Ok(exists) => format!("result: {exists}"),
        Err(e) => format!("error: {e}"),
    };

    let mut future = ExistsResultWithHandler::new(rx, handler);

    // Drop the sender without sending anything
    drop(tx);

    // Poll should handle the dropped sender gracefully
    let waker = create_test_waker();
    let mut cx = Context::from_waker(&waker);
    let result = Pin::new(&mut future).poll(&mut cx);

    // Should complete with some result (not panic)
    assert!(matches!(result, Poll::Ready(_)));

    // Subsequent polls should return Pending (not panic)
    let result = Pin::new(&mut future).poll(&mut cx);
    assert!(matches!(result, Poll::Pending));
}

#[tokio::test]
async fn test_concurrent_polling_safety() {
    let (tx, rx) = oneshot::channel();
    let handler = |result: Result<Vec<String>, cryypt_key::KeyError>| match result {
        Ok(keys) => format!("concurrent: {} items", keys.len()),
        Err(e) => format!("error: {e}"),
    };

    let mut future = ListResultWithHandler::new(rx, handler);

    // Send result
    tx.send(Ok(vec!["test".to_string()])).unwrap();

    // Simulate rapid polling (should not panic)
    let waker = create_test_waker();
    let mut cx = Context::from_waker(&waker);
    for _ in 0..10 {
        let _ = Pin::new(&mut future).poll(&mut cx);
    }

    // All polls after the first should return Pending
    let result = Pin::new(&mut future).poll(&mut cx);
    assert!(matches!(result, Poll::Pending));
}
