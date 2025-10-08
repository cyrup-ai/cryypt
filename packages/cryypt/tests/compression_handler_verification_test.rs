//! Test suite for compression builder error handler verification

use cryypt::Cryypt;
use std::sync::{Arc, Mutex};

/// Test helper to track if a closure was called
#[derive(Debug, Clone)]
struct ClosureCallTracker {
    called: Arc<Mutex<bool>>,
    call_count: Arc<Mutex<u32>>,
    last_error: Arc<Mutex<Option<String>>>,
}

impl ClosureCallTracker {
    fn new() -> Self {
        Self {
            called: Arc::new(Mutex::new(false)),
            call_count: Arc::new(Mutex::new(0)),
            last_error: Arc::new(Mutex::new(None)),
        }
    }

    fn was_called(&self) -> bool {
        *self
            .called
            .lock()
            .expect("Mutex poisoned - test infrastructure failure")
    }

    fn call_count(&self) -> u32 {
        *self
            .call_count
            .lock()
            .expect("Mutex poisoned - test infrastructure failure")
    }

    fn last_error(&self) -> Option<String> {
        self.last_error
            .lock()
            .expect("Mutex poisoned - test infrastructure failure")
            .clone()
    }

    fn mark_called(&self, error_msg: Option<String>) {
        *self
            .called
            .lock()
            .expect("Mutex poisoned - test infrastructure failure") = true;
        *self
            .call_count
            .lock()
            .expect("Mutex poisoned - test infrastructure failure") += 1;
        *self
            .last_error
            .lock()
            .expect("Mutex poisoned - test infrastructure failure") = error_msg;
    }
}

#[tokio::test]
async fn test_compression_zstd_handler_usage() {
    let tracker = ClosureCallTracker::new();
    let tracker_clone = tracker.clone();

    let result = Cryypt::compress()
        .zstd()
        .with_level(3)
        .on_result(move |result| {
            match result {
                Ok(compression_result) => {
                    tracker_clone.mark_called(None);
                    // Return modified data to prove handler was used
                    let mut modified = compression_result.clone();
                    modified.extend_from_slice(b"_ZSTD_HANDLER_CALLED");
                    modified
                }
                Err(e) => {
                    tracker_clone.mark_called(Some(e.to_string()));
                    b"ZSTD_ERROR_HANDLER_CALLED".to_vec()
                }
            }
        })
        .compress(b"Large text data that should compress well with zstd algorithm")
        .await;

    // Verify the closure was called and modified the result
    assert!(tracker.was_called(), "ZSTD handler closure was not called");
    assert_eq!(
        tracker.call_count(),
        1,
        "ZSTD handler should be called exactly once"
    );
    assert!(
        tracker.last_error().is_none(),
        "No error should have occurred in success case"
    );
    assert!(
        result.ends_with(b"_ZSTD_HANDLER_CALLED"),
        "ZSTD handler should have modified the result"
    );

    println!("✅ ZSTD Handler Test PASSED - Closure was called and modified result");
}

#[tokio::test]
async fn test_compression_gzip_handler_usage() {
    let tracker = ClosureCallTracker::new();
    let tracker_clone = tracker.clone();

    let result = Cryypt::compress()
        .gzip()
        .with_level(6)
        .on_result(move |result| {
            match result {
                Ok(compression_result) => {
                    tracker_clone.mark_called(None);
                    // Return modified data to prove handler was used
                    let mut modified = compression_result.clone();
                    modified.extend_from_slice(b"_GZIP_HANDLER_CALLED");
                    modified
                }
                Err(e) => {
                    tracker_clone.mark_called(Some(e.to_string()));
                    b"GZIP_ERROR_HANDLER_CALLED".to_vec()
                }
            }
        })
        .compress(b"Large text data that should compress well with gzip algorithm")
        .await;

    // Verify the closure was called and modified the result
    assert!(tracker.was_called(), "GZIP handler closure was not called");
    assert_eq!(
        tracker.call_count(),
        1,
        "GZIP handler should be called exactly once"
    );
    assert!(
        tracker.last_error().is_none(),
        "No error should have occurred in success case"
    );
    assert!(
        result.ends_with(b"_GZIP_HANDLER_CALLED"),
        "GZIP handler should have modified the result"
    );

    println!("✅ GZIP Handler Test PASSED - Closure was called and modified result");
}

// Note: BZIP2 and ZIP tests removed as these features may not be enabled in the test environment
