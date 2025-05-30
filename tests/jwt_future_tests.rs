//! Tests specifically for JWT Future types and async behavior
//!
//! This test suite focuses on the custom Future implementations
//! and their async characteristics.

use chrono::Duration;
use cryypt::jwt::*;
use futures::future::{Either, FutureExt, select};
use futures::pin_mut;
use serde_json::json;
use std::future::Future;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};
use std::time::Duration as StdDuration;
use tokio::time::{sleep, timeout};

/// Helper to create a simple waker for testing
fn create_test_waker() -> Waker {
    use std::sync::Arc;
    use std::task::{Wake, Waker};

    struct TestWaker;

    impl Wake for TestWaker {
        fn wake(self: Arc<Self>) {}
        fn wake_by_ref(self: &Arc<Self>) {}
    }

    Waker::from(Arc::new(TestWaker))
}

#[tokio::test]
async fn test_token_generation_future_basic() {
    let key = Hs256Key::random();
    let generator = Generator::new(key);

    let claims = ClaimsBuilder::new()
        .subject("future_test")
        .expires_in(Duration::hours(1))
        .issued_now()
        .build();

    // Get the future
    let future = generator.token(&claims);

    // Await it
    let token = future.await.unwrap();
    assert!(!token.is_empty());
    assert_eq!(token.matches('.').count(), 2);
}

#[tokio::test]
async fn test_token_verification_future_basic() {
    let key = Hs256Key::random();
    let generator = Generator::new(key);

    let claims = ClaimsBuilder::new()
        .subject("verify_future")
        .expires_in(Duration::hours(1))
        .issued_now()
        .build();

    let token = generator.token(&claims).await.unwrap();

    // Get verification future
    let future = generator.verify(token);

    // Await it
    let verified = future.await.unwrap();
    assert_eq!(verified.sub, "verify_future");
}

#[tokio::test]
async fn test_future_select_racing() {
    let key1 = Hs256Key::random();
    let key2 = Es256Key::new();

    let gen1 = Generator::new(key1);
    let gen2 = Generator::new(key2);

    let claims = ClaimsBuilder::new()
        .subject("race_test")
        .expires_in(Duration::hours(1))
        .issued_now()
        .build();

    // Race two token generations
    let future1 = gen1.token(&claims);
    let future2 = gen2.token(&claims);

    pin_mut!(future1);
    pin_mut!(future2);

    match select(future1, future2).await {
        Either::Left((token, _)) => {
            assert!(!token.unwrap().is_empty());
        }
        Either::Right((token, _)) => {
            assert!(!token.unwrap().is_empty());
        }
    }
}

#[tokio::test]
async fn test_future_timeout() {
    let key = Hs256Key::random();
    let generator = Generator::new(key);

    let claims = ClaimsBuilder::new()
        .subject("timeout_test")
        .expires_in(Duration::hours(1))
        .issued_now()
        .build();

    // Token generation should complete quickly
    let result = timeout(StdDuration::from_secs(5), generator.token(&claims)).await;

    assert!(result.is_ok());
    assert!(result.unwrap().is_ok());
}

#[tokio::test]
async fn test_multiple_concurrent_futures() {
    let key = Hs256Key::random();
    let generator = Arc::new(Generator::new(key));

    let mut futures = Vec::new();

    // Create 100 concurrent token generation futures
    for i in 0..100 {
        let gen_clone = generator.clone();
        let claims = ClaimsBuilder::new()
            .subject(format!("concurrent_{}", i))
            .expires_in(Duration::hours(1))
            .issued_now()
            .claim("index".to_string(), json!(i))
            .build();

        futures.push(gen_clone.token(&claims));
    }

    // Await all futures
    let tokens = futures::future::try_join_all(futures).await.unwrap();
    assert_eq!(tokens.len(), 100);

    // Verify a few tokens
    for (i, token) in tokens.iter().enumerate().take(10) {
        let verified = generator.verify(token).await.unwrap();
        assert!(verified.sub.contains(&i.to_string()));
    }
}

#[tokio::test]
async fn test_cleanup_start_future() {
    let key = Hs256Key::random();
    let revocation = Revocation::wrap(key);

    // Get cleanup future
    let cleanup_future = revocation.start_cleanup(Duration::seconds(1));

    // Await it
    cleanup_future.await;

    // Cleanup should be running now
    // Generate and revoke a token to test
    let claims = ClaimsBuilder::new()
        .subject("cleanup_test")
        .expires_in(Duration::seconds(1))
        .issued_now()
        .build();

    let token = revocation.token(&claims).await.unwrap();
    revocation.revoke(&token, "test cleanup");

    // Wait for expiry and cleanup
    sleep(StdDuration::from_secs(2)).await;

    // Stop cleanup
    revocation.stop_cleanup().await;
}

#[tokio::test]
async fn test_future_error_propagation() {
    let key = Hs256Key::random();
    let generator = Generator::new(key);

    // Test with invalid token
    let future = generator.verify("invalid.token");
    let result = future.await;

    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), JwtError::Malformed));

    // Test with expired token
    let expired_claims = ClaimsBuilder::new()
        .subject("expired")
        .expires_in(Duration::seconds(-10))
        .issued_now()
        .build();

    let token = generator.token(&expired_claims).await.unwrap();
    let verify_future = generator.verify(token);
    let result = verify_future.await;

    assert!(matches!(result.unwrap_err(), JwtError::Expired));
}

#[tokio::test]
async fn test_future_chaining() {
    let key = Hs256Key::random();
    let generator = Arc::new(Generator::new(key));

    let claims = ClaimsBuilder::new()
        .subject("chain_test")
        .expires_in(Duration::hours(1))
        .issued_now()
        .claim("step".to_string(), json!(1))
        .build();

    // Chain token generation and verification
    let generator_clone = generator.clone();
    let result = generator
        .token(&claims)
        .then(move |token_result| async move {
            match token_result {
                Ok(token) => generator_clone.verify(token).await,
                Err(e) => Err(e),
            }
        })
        .await;

    assert!(result.is_ok());
    assert_eq!(result.unwrap().sub, "chain_test");
}

#[tokio::test]
async fn test_future_cancellation() {
    let key = Hs256Key::random();
    let generator = Arc::new(Generator::new(key));

    // Create a future but drop it before awaiting
    {
        let claims = ClaimsBuilder::new()
            .subject("cancel")
            .expires_in(Duration::hours(1))
            .issued_now()
            .build();

        let _future = generator.token(&claims);
        // Future dropped here
    }

    // Generator should still work
    let claims = ClaimsBuilder::new()
        .subject("after_cancel")
        .expires_in(Duration::hours(1))
        .issued_now()
        .build();

    let token = generator.token(&claims).await.unwrap();
    assert!(!token.is_empty());
}

#[tokio::test]
async fn test_revocation_future_ordering() {
    let key = Hs256Key::random();
    let revocation = Arc::new(Revocation::wrap(key));

    let claims = ClaimsBuilder::new()
        .subject("order_test")
        .expires_in(Duration::hours(1))
        .issued_now()
        .build();

    // Generate token
    let token = revocation.token(&claims).await.unwrap();

    // Start verification and revocation concurrently
    let rev_clone = revocation.clone();
    let token_clone = token.clone();

    let verify_future = revocation.verify(token.clone());
    let revoke_task = tokio::spawn(async move {
        // Small delay to let verification start
        sleep(StdDuration::from_millis(10)).await;
        rev_clone.revoke(&token_clone, "concurrent revoke");
    });

    // Verification might succeed or fail depending on timing
    let _verify_result = verify_future.await;
    revoke_task.await.unwrap();

    // After revocation, verification should definitely fail
    let result = revocation.verify(token).await;
    assert!(matches!(result, Err(JwtError::Revoked)));
}

#[tokio::test]
async fn test_future_with_different_claims_types() {
    let key = Hs256Key::random();
    let generator = Generator::new(key);

    // Test with various claim value types
    let claims = ClaimsBuilder::new()
        .subject("types_test")
        .expires_in(Duration::hours(1))
        .issued_now()
        .claim("string".to_string(), json!("value"))
        .claim("number".to_string(), json!(42))
        .claim("float".to_string(), json!(3.14))
        .claim("bool".to_string(), json!(true))
        .claim("null".to_string(), json!(null))
        .claim("array".to_string(), json!([1, 2, 3]))
        .claim("object".to_string(), json!({"nested": "value"}))
        .build();

    let token_future = generator.token(&claims);
    let token = token_future.await.unwrap();

    let verify_future = generator.verify(token);
    let verified = verify_future.await.unwrap();

    assert_eq!(verified.extra.get("string"), Some(&json!("value")));
    assert_eq!(verified.extra.get("number"), Some(&json!(42)));
    assert_eq!(verified.extra.get("bool"), Some(&json!(true)));
}

#[tokio::test]
async fn test_nested_future_spawning() {
    let key = Hs256Key::random();
    let generator = Arc::new(Generator::new(key));

    let handle = tokio::spawn({
        let gen_clone = generator.clone();
        async move {
            let claims = ClaimsBuilder::new()
                .subject("nested_spawn")
                .expires_in(Duration::hours(1))
                .issued_now()
                .build();

            let token = gen_clone.token(&claims).await.unwrap();

            // Spawn another task for verification
            let gen_clone2 = gen_clone.clone();
            let verify_handle = tokio::spawn(async move { gen_clone2.verify(token).await });

            verify_handle.await.unwrap()
        }
    });

    let result = handle.await.unwrap();
    assert!(result.is_ok());
    assert_eq!(result.unwrap().sub, "nested_spawn");
}

#[tokio::test]
async fn test_future_join_combinations() {
    let hs_key = Hs256Key::random();
    let es_key = Es256Key::new();

    let hs_gen = Generator::new(hs_key);
    let es_gen = Generator::new(es_key);

    let claims = ClaimsBuilder::new()
        .subject("join_test")
        .expires_in(Duration::hours(1))
        .issued_now()
        .build();

    // Generate tokens with both algorithms concurrently
    let (hs_token, es_token) = tokio::join!(hs_gen.token(&claims), es_gen.token(&claims));

    let hs_token = hs_token.unwrap();
    let es_token = es_token.unwrap();

    // Verify both tokens concurrently
    let (hs_verify, es_verify) = tokio::join!(hs_gen.verify(&hs_token), es_gen.verify(&es_token));

    assert!(hs_verify.is_ok());
    assert!(es_verify.is_ok());

    // Cross-verification should fail
    let (hs_cross, es_cross) = tokio::join!(hs_gen.verify(&es_token), es_gen.verify(&hs_token));

    assert!(matches!(hs_cross, Err(JwtError::AlgorithmMismatch { .. })));
    assert!(matches!(es_cross, Err(JwtError::AlgorithmMismatch { .. })));
}

#[tokio::test]
async fn test_future_with_tokio_select() {
    let key = Hs256Key::random();
    let generator = Arc::new(Generator::new(key));

    let claims = ClaimsBuilder::new()
        .subject("select_test")
        .expires_in(Duration::hours(1))
        .issued_now()
        .build();

    let generator1 = generator.clone();
    let generator2 = generator.clone();

    tokio::select! {
        token1 = generator1.token(&claims) => {
            assert!(token1.is_ok());
        }
        token2 = generator2.token(&claims) => {
            assert!(token2.is_ok());
        }
    }
}

#[tokio::test]
async fn test_manual_future_polling() {
    let key = Hs256Key::random();
    let generator = Generator::new(key);

    let claims = ClaimsBuilder::new()
        .subject("poll_test")
        .expires_in(Duration::hours(1))
        .issued_now()
        .build();

    let mut future = Box::pin(generator.token(&claims));
    let waker = create_test_waker();
    let mut context = Context::from_waker(&waker);

    // Poll the future manually
    loop {
        match future.as_mut().poll(&mut context) {
            Poll::Ready(result) => {
                assert!(result.is_ok());
                break;
            }
            Poll::Pending => {
                // In a real scenario, we'd wait for the waker
                // For testing, we'll just yield
                tokio::task::yield_now().await;
            }
        }
    }
}
