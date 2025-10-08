//! Tests for `cipher_result` Future error handling - ensuring no panics occur

use cryypt_cipher::CipherError;
use cryypt_cipher::{CipherResult, CipherResultWithHandler};
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
async fn test_cipher_result_with_handler_multiple_polls_after_completion() {
    let result = Ok(vec![1, 2, 3, 4]);
    let cipher_result = CipherResult::ready(result);

    let handler = |result: Result<Vec<u8>, CipherError>| match result {
        Ok(data) => format!("success: {} bytes", data.len()),
        Err(e) => format!("error: {e}"),
    };

    let mut future = cipher_result.on_result(handler);

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
async fn test_cipher_result_with_handler_error_case() {
    let error = CipherError::Internal("test error".to_string());
    let cipher_result = CipherResult::error(error);

    let handler = |result: Result<Vec<u8>, CipherError>| match result {
        Ok(_) => "unexpected success".to_string(),
        Err(e) => format!("handled error: {e}"),
    };

    let mut future = cipher_result.on_result(handler);

    // First poll should complete with error handling
    let waker = create_test_waker();
    let mut cx = Context::from_waker(&waker);
    let result = Pin::new(&mut future).poll(&mut cx);
    assert!(matches!(result, Poll::Ready(_)));

    // Subsequent polls should return Pending (not panic)
    let result = Pin::new(&mut future).poll(&mut cx);
    assert!(matches!(result, Poll::Pending));
}

#[tokio::test]
async fn test_cipher_result_sender_dropped() {
    let (tx, rx) = oneshot::channel();
    let handler = |result: Result<Vec<u8>, CipherError>| match result {
        Ok(data) => format!("got {} bytes", data.len()),
        Err(e) => format!("error: {e}"),
    };

    let cipher_result = CipherResult::from_receiver(rx);
    let mut future = cipher_result.on_result(handler);

    // Drop the sender without sending anything
    drop(tx);

    // Poll should handle the dropped sender gracefully
    let waker = create_test_waker();
    let mut cx = Context::from_waker(&waker);
    let result = Pin::new(&mut future).poll(&mut cx);

    // Should complete with error handling (not panic)
    assert!(matches!(result, Poll::Ready(_)));

    // Subsequent polls should return Pending (not panic)
    let result = Pin::new(&mut future).poll(&mut cx);
    assert!(matches!(result, Poll::Pending));
}

#[tokio::test]
async fn test_cipher_result_rapid_polling() {
    let result = Ok(vec![5, 6, 7, 8]);
    let cipher_result = CipherResult::ready(result);

    let handler = |result: Result<Vec<u8>, CipherError>| match result {
        Ok(data) => data.len(),
        Err(_) => 0,
    };

    let mut future = cipher_result.on_result(handler);

    // Simulate rapid polling (should not panic)
    let waker = create_test_waker();
    let mut cx = Context::from_waker(&waker);
    let mut completed = false;

    for _ in 0..10 {
        match Pin::new(&mut future).poll(&mut cx) {
            Poll::Ready(_) if !completed => {
                completed = true;
            }
            Poll::Ready(_) => {
                panic!("Future completed multiple times");
            }
            Poll::Pending => {
                // Expected after completion
            }
        }
    }

    assert!(completed, "Future should have completed at least once");
}

#[tokio::test]
async fn test_cipher_result_without_handler_multiple_polls() {
    let result = Ok(vec![9, 10, 11]);
    let mut cipher_result = CipherResult::ready(result);

    // First poll should complete successfully
    let waker = create_test_waker();
    let mut cx = Context::from_waker(&waker);
    let result = Pin::new(&mut cipher_result).poll(&mut cx);
    assert!(matches!(result, Poll::Ready(Ok(_))));

    // CipherResult without handler can be polled multiple times safely
    // (it doesn't have the same completion tracking as CipherResultWithHandler)
    let result = Pin::new(&mut cipher_result).poll(&mut cx);
    // This may return Ready again or Pending depending on implementation
    // The key is that it shouldn't panic
}

#[tokio::test]
async fn test_cipher_result_error_without_handler() {
    let error = CipherError::Encryption("test encryption error".to_string());
    let mut cipher_result = CipherResult::error(error);

    // Poll should return the error
    let waker = create_test_waker();
    let mut cx = Context::from_waker(&waker);
    let result = Pin::new(&mut cipher_result).poll(&mut cx);

    match result {
        Poll::Ready(Err(CipherError::Encryption(msg))) => {
            assert_eq!(msg, "test encryption error");
        }
        _ => panic!("Expected encryption error"),
    }
}
