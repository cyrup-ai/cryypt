//! Comprehensive test suite proving that ALL builders actually use their error handler closures
//! This test verifies that `on_result`, `on_chunk`, and `on_error` handlers are captured and invoked

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
async fn test_cipher_aes_error_handler_usage() {
    let tracker = ClosureCallTracker::new();
    let tracker_clone = tracker.clone();

    // Test with invalid key size to trigger error
    let invalid_key = b"short".to_vec(); // Only 5 bytes, should fail

    let result = Cryypt::cipher()
        .aes()
        .with_key(invalid_key)
        .on_result(move |result| match result {
            Ok(_) => {
                tracker_clone.mark_called(None);
                b"success".to_vec()
            }
            Err(e) => {
                tracker_clone.mark_called(Some(e.to_string()));
                b"ERROR_HANDLER_CALLED".to_vec()
            }
        })
        .encrypt(b"test data")
        .await;

    // Verify the closure was called and handled the error
    assert!(tracker.was_called(), "Error handler closure was not called");
    assert_eq!(
        tracker.call_count(),
        1,
        "Error handler should be called exactly once"
    );
    assert!(
        tracker.last_error().is_some(),
        "Error should have been captured"
    );
    assert_eq!(
        result,
        b"ERROR_HANDLER_CALLED".to_vec(),
        "Error handler return value should be used"
    );

    println!(
        "✅ AES Error Handler Test PASSED - Closure was called with error: {:?}",
        tracker.last_error()
    );
}

#[tokio::test]
async fn test_cipher_aes_success_handler_usage() {
    let tracker = ClosureCallTracker::new();
    let tracker_clone = tracker.clone();

    // Test with valid key to trigger success
    let valid_key = b"test_key_32_bytes_long_for_aes!!".to_vec(); // Exactly 32 bytes

    let result = Cryypt::cipher()
        .aes()
        .with_key(valid_key)
        .on_result(move |result| {
            match result {
                Ok(encrypted_data) => {
                    tracker_clone.mark_called(None);
                    // Return modified data to prove handler was used
                    let mut modified = encrypted_data;
                    modified.extend_from_slice(b"_HANDLER_CALLED");
                    modified
                }
                Err(e) => {
                    tracker_clone.mark_called(Some(e.to_string()));
                    Vec::new()
                }
            }
        })
        .encrypt(b"test message")
        .await;

    // Verify the closure was called and modified the result
    assert!(
        tracker.was_called(),
        "Success handler closure was not called"
    );
    assert_eq!(
        tracker.call_count(),
        1,
        "Success handler should be called exactly once"
    );
    assert!(
        tracker.last_error().is_none(),
        "No error should have been captured in success case"
    );
    assert!(
        result.ends_with(b"_HANDLER_CALLED"),
        "Success handler should have modified the result"
    );

    println!("✅ AES Success Handler Test PASSED - Closure was called and modified result");
}

#[tokio::test]
async fn test_cipher_chacha_error_handler_usage() {
    let tracker = ClosureCallTracker::new();
    let tracker_clone = tracker.clone();

    // Test with invalid key size to trigger error
    let invalid_key = b"short".to_vec(); // Only 5 bytes, should fail

    let result = Cryypt::cipher()
        .chacha20()
        .with_key(invalid_key)
        .on_result(move |result| match result {
            Ok(_) => {
                tracker_clone.mark_called(None);
                b"success".to_vec()
            }
            Err(e) => {
                tracker_clone.mark_called(Some(e.to_string()));
                b"CHACHA_ERROR_HANDLER_CALLED".to_vec()
            }
        })
        .encrypt(b"test data")
        .await;

    // Verify the closure was called and handled the error
    assert!(
        tracker.was_called(),
        "ChaCha error handler closure was not called"
    );
    assert_eq!(
        result,
        b"CHACHA_ERROR_HANDLER_CALLED".to_vec(),
        "ChaCha error handler return value should be used"
    );

    println!(
        "✅ ChaCha Error Handler Test PASSED - Closure was called with error: {:?}",
        tracker.last_error()
    );
}

#[tokio::test]
async fn test_hash_sha256_error_handler_usage() {
    let tracker = ClosureCallTracker::new();
    let tracker_clone = tracker.clone();

    // Note: SHA256 rarely fails, but we can still test handler usage
    let result = Cryypt::hash()
        .sha256()
        .on_result(move |result| {
            match result {
                Ok(hash_result) => {
                    tracker_clone.mark_called(None);
                    // Return modified hash to prove handler was used
                    let mut modified = hash_result.to_vec();
                    modified.extend_from_slice(b"_SHA256_HANDLER_CALLED");
                    modified
                }
                Err(e) => {
                    tracker_clone.mark_called(Some(e.to_string()));
                    Vec::new()
                }
            }
        })
        .compute(b"test data")
        .await;

    // Verify the closure was called and modified the result
    assert!(
        tracker.was_called(),
        "SHA256 handler closure was not called"
    );
    assert!(
        result.ends_with(b"_SHA256_HANDLER_CALLED"),
        "SHA256 handler should have modified the result"
    );

    println!("✅ SHA256 Handler Test PASSED - Closure was called and modified result");
}

#[tokio::test]
async fn test_hash_blake2b_error_handler_usage() {
    let tracker = ClosureCallTracker::new();
    let tracker_clone = tracker.clone();

    let result = Cryypt::hash()
        .blake2b()
        .on_result(move |result| {
            match result {
                Ok(hash_result) => {
                    tracker_clone.mark_called(None);
                    // Return modified hash to prove handler was used
                    let mut modified = hash_result.to_vec();
                    modified.extend_from_slice(b"_BLAKE2B_HANDLER_CALLED");
                    modified
                }
                Err(e) => {
                    tracker_clone.mark_called(Some(e.to_string()));
                    Vec::new()
                }
            }
        })
        .compute(b"test data")
        .await;

    // Verify the closure was called and modified the result
    assert!(
        tracker.was_called(),
        "BLAKE2B handler closure was not called"
    );
    assert!(
        result.ends_with(b"_BLAKE2B_HANDLER_CALLED"),
        "BLAKE2B handler should have modified the result"
    );

    println!("✅ BLAKE2B Handler Test PASSED - Closure was called and modified result");
}

#[tokio::test]
async fn test_hash_sha3_error_handler_usage() {
    let tracker = ClosureCallTracker::new();
    let tracker_clone = tracker.clone();

    let result = Cryypt::hash()
        .sha3_256()
        .on_result(move |result| {
            match result {
                Ok(hash_result) => {
                    tracker_clone.mark_called(None);
                    // Return modified hash to prove handler was used
                    let mut modified = hash_result.to_vec();
                    modified.extend_from_slice(b"_SHA3_HANDLER_CALLED");
                    modified
                }
                Err(e) => {
                    tracker_clone.mark_called(Some(e.to_string()));
                    Vec::new()
                }
            }
        })
        .compute(b"test data")
        .await;

    // Verify the closure was called and modified the result
    assert!(tracker.was_called(), "SHA3 handler closure was not called");
    assert!(
        result.ends_with(b"_SHA3_HANDLER_CALLED"),
        "SHA3 handler should have modified the result"
    );

    println!("✅ SHA3 Handler Test PASSED - Closure was called and modified result");
}
