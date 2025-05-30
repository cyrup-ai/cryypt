//! JWT edge case tests
//!
//! This test suite covers edge cases, boundary conditions, and stress tests
//! for the JWT implementation.

use chrono::{Duration, Utc};
use cryypt::jwt::*;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Semaphore;

#[tokio::test]
async fn test_extreme_timestamps() {
    let key = Hs256Key::random();
    let generator = Generator::new(key);
    
    // Test with maximum timestamp values
    let max_timestamp = i64::MAX / 1000; // Avoid overflow in calculations
    let claims = Claims {
        sub: "test".to_string(),
        exp: max_timestamp,
        iat: max_timestamp - 3600,
        iss: None,
        aud: None,
        nbf: None,
        jti: None,
        extra: HashMap::new(),
    };
    
    let token = generator.token(&claims).await.unwrap();
    
    // Should fail verification due to being too far in future
    let result = generator.verify(&token).await;
    assert!(result.is_ok()); // Will pass because exp is in far future
    
    // Test with minimum (negative) timestamps
    let min_claims = Claims {
        sub: "test".to_string(),
        exp: -1, // Already expired
        iat: -3600,
        iss: None,
        aud: None,
        nbf: None,
        jti: None,
        extra: HashMap::new(),
    };
    
    let token = generator.token(&min_claims).await.unwrap();
    let result = generator.verify(&token).await;
    assert!(matches!(result, Err(JwtError::Expired)));
}

#[tokio::test]
async fn test_unicode_and_special_characters() {
    let key = Hs256Key::random();
    let generator = Generator::new(key);
    
    // Test various Unicode characters and edge cases
    let special_subjects = vec![
        "user@example.com",
        "user+tag@example.com",
        "用户名",  // Chinese
        "المستخدم", // Arabic
        "ユーザー", // Japanese
        "🦀🔐🎉", // Emojis
        "user\nwith\nnewlines",
        "user\twith\ttabs",
        "user with spaces",
        r#"user"with"quotes"#,
        "user'with'apostrophes",
        "user\\with\\backslashes",
        "",  // Empty string
    ];
    
    for subject in special_subjects {
        let claims = ClaimsBuilder::new()
            .subject(subject)
            .expires_in(Duration::hours(1))
            .issued_now()
            .issuer("测试发行者") // Unicode issuer
            .audience(vec!["🌍".to_string(), "api-😀".to_string()])
            .jwt_id("id-🔑")
            .claim("emoji".to_string(), json!("🎯"))
            .claim("unicode".to_string(), json!({
                "chinese": "你好",
                "arabic": "مرحبا",
                "russian": "Привет"
            }))
            .build();
        
        let token = generator.token(&claims).await.unwrap();
        let verified = generator.verify(&token).await.unwrap();
        
        assert_eq!(verified.sub, subject);
        assert_eq!(verified.iss, Some("测试发行者".to_string()));
        assert_eq!(verified.jti, Some("id-🔑".to_string()));
    }
}

#[tokio::test]
async fn test_very_large_payloads() {
    let key = Hs256Key::random();
    let generator = Generator::new(key);
    
    // Create a very large custom claim (1MB of data)
    let large_data: String = "x".repeat(1024 * 1024);
    let mut large_extra = HashMap::new();
    large_extra.insert("large_field".to_string(), json!(large_data));
    
    // Also test with many small claims
    for i in 0..1000 {
        large_extra.insert(
            format!("field_{}", i),
            json!({
                "index": i,
                "data": format!("value_{}", i),
                "nested": {
                    "level1": {
                        "level2": {
                            "level3": format!("deep_value_{}", i)
                        }
                    }
                }
            })
        );
    }
    
    let claims = ClaimsBuilder::new()
        .subject("user")
        .expires_in(Duration::hours(1))
        .issued_now()
        .build();
    
    // Manually set the large extra data
    let mut claims = claims;
    claims.extra = large_extra;
    
    let token = generator.token(&claims).await.unwrap();
    assert!(!token.is_empty());
    
    // Verify the large token
    let verified = generator.verify(&token).await.unwrap();
    assert_eq!(verified.sub, "user");
    assert_eq!(verified.extra.len(), 1001); // 1 large field + 1000 small fields
}

#[tokio::test]
async fn test_concurrent_key_rotation() {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    
    let rotation_count = Arc::new(AtomicUsize::new(0));
    let should_rotate = Arc::new(AtomicBool::new(false));
    
    let rotation_count_clone = rotation_count.clone();
    let should_rotate_clone = should_rotate.clone();
    
    let rotator = Rotator::new(
        Box::new(Hs256Key::random()),
        move || {
            rotation_count_clone.fetch_add(1, Ordering::SeqCst);
            (Box::new(Hs256Key::random()) as Box<dyn Signer>, Utc::now() + Duration::hours(1))
        },
        move || should_rotate_clone.load(Ordering::SeqCst),
    );
    
    let generator = Arc::new(Generator::new(rotator));
    
    // Spawn many concurrent operations
    let mut handles = vec![];
    
    for i in 0..100 {
        let gen_clone = generator.clone();
        let should_rotate = should_rotate.clone();
        
        let handle = tokio::spawn(async move {
            let claims = ClaimsBuilder::new()
                .subject(format!("user{}", i))
                .expires_in(Duration::hours(1))
                .issued_now()
                .build();
            
            // Trigger rotation halfway through
            if i == 50 {
                should_rotate.store(true, Ordering::SeqCst);
            }
            
            gen_clone.token(&claims).await
        });
        
        handles.push(handle);
    }
    
    let results: Vec<_> = futures::future::try_join_all(handles)
        .await
        .unwrap()
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    
    assert_eq!(results.len(), 100);
    assert!(rotation_count.load(Ordering::SeqCst) > 0);
}

#[tokio::test]
async fn test_revocation_with_invalid_tokens() {
    let key = Hs256Key::random();
    let revocation = Revocation::wrap(key);
    
    // Test revoking various invalid tokens
    let long_string = "x".repeat(10000);
    let invalid_tokens = vec![
        "",
        "invalid",
        "invalid.token",
        "a.b.c.d", // Too many parts
        "....", // Only dots
        &long_string, // Very long string
    ];
    
    for token in invalid_tokens {
        // Should not panic
        revocation.revoke(token, "Testing invalid token revocation");
    }
    
    // Valid token should still work
    let claims = ClaimsBuilder::new()
        .subject("user")
        .expires_in(Duration::hours(1))
        .issued_now()
        .build();
    
    let valid_token = revocation.token(&claims).await.unwrap();
    let result = revocation.verify(&valid_token).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_boundary_validation_options() {
    // Test with extreme validation options
    let extreme_opts = ValidationOptions {
        leeway: Duration::days(365 * 100), // 100 years
        validate_exp: true,
        validate_nbf: true,
        required_claims: (0..100).map(|i| format!("claim_{}", i)).collect(),
        allowed_algorithms: vec!["HS256"],
        expected_issuer: Some("x".repeat(1000)), // Very long issuer
        expected_audience: Some((0..100).map(|i| format!("aud_{}", i)).collect()),
    };
    
    let generator = Generator::new(Hs256Key::random())
        .with_validation_options(extreme_opts);
    
    // Create claims that satisfy all requirements
    let mut builder = ClaimsBuilder::new()
        .subject("user")
        .expires_in(Duration::days(-1)) // Expired, but within 100 year leeway
        .issued_now()
        .issuer("x".repeat(1000));
    
    // Add all required claims
    for i in 0..100 {
        builder = builder.claim(format!("claim_{}", i), json!(i));
    }
    
    // Add all expected audiences
    builder = builder.audience((0..100).map(|i| format!("aud_{}", i)).collect());
    
    let claims = builder.build();
    let token = generator.token(&claims).await.unwrap();
    
    // Should pass validation despite being expired due to huge leeway
    let result = generator.verify(&token).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_stress_concurrent_operations() {
    let key = Hs256Key::random();
    let revocation = Arc::new(Revocation::wrap(key));
    
    // Limit concurrent operations to avoid resource exhaustion
    let semaphore = Arc::new(Semaphore::new(50));
    let mut handles = vec![];
    
    // Start cleanup task
    revocation.start_cleanup(Duration::seconds(1)).await;
    
    // Spawn many concurrent operations
    for i in 0..1000 {
        let rev = revocation.clone();
        let sem = semaphore.clone();
        
        let handle = tokio::spawn(async move {
            let _permit = sem.acquire().await.unwrap();
            
            let claims = ClaimsBuilder::new()
                .subject(format!("stress_user_{}", i))
                .expires_in(Duration::seconds(if i % 2 == 0 { 1 } else { 3600 }))
                .issued_now()
                .claim("operation".to_string(), json!(i))
                .build();
            
            let token = rev.token(&claims).await.unwrap();
            
            // Revoke every 3rd token
            if i % 3 == 0 {
                rev.revoke(&token, &format!("Stress test revoke {}", i));
            }
            
            // Try to verify
            let _ = rev.verify(&token).await;
            
            // Manually trigger cleanup occasionally
            if i % 100 == 0 {
                rev.cleanup_expired();
            }
        });
        
        handles.push(handle);
    }
    
    futures::future::join_all(handles).await;
    
    // Stop cleanup
    revocation.stop_cleanup().await;
}

#[tokio::test]
async fn test_algorithm_mismatch_detailed() {
    let hs256_key = Hs256Key::random();
    let es256_key = Es256Key::new();
    
    let hs_gen = Generator::new(hs256_key);
    let es_gen = Generator::new(es256_key);
    
    let claims = ClaimsBuilder::new()
        .subject("test")
        .expires_in(Duration::hours(1))
        .issued_now()
        .build();
    
    // Generate tokens with different algorithms
    let hs_token = hs_gen.token(&claims).await.unwrap();
    let es_token = es_gen.token(&claims).await.unwrap();
    
    // Cross-verify (should fail with algorithm mismatch)
    match hs_gen.verify(&es_token).await {
        Err(JwtError::AlgorithmMismatch { expected, got }) => {
            assert_eq!(expected, "HS256");
            assert_eq!(got, "ES256");
        }
        _ => panic!("Expected AlgorithmMismatch error"),
    }
    
    match es_gen.verify(&hs_token).await {
        Err(JwtError::AlgorithmMismatch { expected, got }) => {
            assert_eq!(expected, "ES256");
            assert_eq!(got, "HS256");
        }
        _ => panic!("Expected AlgorithmMismatch error"),
    }
}

#[tokio::test]
async fn test_zero_duration_tokens() {
    let key = Hs256Key::random();
    let generator = Generator::new(key);
    
    // Token that expires immediately
    let instant_expire = ClaimsBuilder::new()
        .subject("instant")
        .expires_in(Duration::zero())
        .issued_now()
        .build();
    
    let token = generator.token(&instant_expire).await.unwrap();
    
    // Should already be expired
    tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
    let result = generator.verify(&token).await;
    assert!(matches!(result, Err(JwtError::Expired)));
}

#[tokio::test]
async fn test_claims_with_null_values() {
    let key = Hs256Key::random();
    let generator = Generator::new(key);
    
    let claims = ClaimsBuilder::new()
        .subject("user")
        .expires_in(Duration::hours(1))
        .issued_now()
        .claim("null_value".to_string(), Value::Null)
        .claim("array_with_null".to_string(), json!([1, null, 3]))
        .claim("object_with_null".to_string(), json!({
            "field": null,
            "nested": {
                "value": null
            }
        }))
        .build();
    
    let token = generator.token(&claims).await.unwrap();
    let verified = generator.verify(&token).await.unwrap();
    
    assert_eq!(verified.extra.get("null_value"), Some(&Value::Null));
    assert_eq!(verified.extra.get("array_with_null"), Some(&json!([1, null, 3])));
}

#[tokio::test]
async fn test_partial_token_corruption() {
    let key = Hs256Key::random();
    let generator = Generator::new(key);
    
    let claims = ClaimsBuilder::new()
        .subject("user")
        .expires_in(Duration::hours(1))
        .issued_now()
        .build();
    
    let token = generator.token(&claims).await.unwrap();
    let parts: Vec<&str> = token.split('.').collect();
    
    // Test corrupting each part
    // Corrupt header
    let corrupt_header = format!("XXX{}.{}.{}", &parts[0][3..], parts[1], parts[2]);
    assert!(generator.verify(&corrupt_header).await.is_err());
    
    // Corrupt payload
    let corrupt_payload = format!("{}.XXX{}.{}", parts[0], &parts[1][3..], parts[2]);
    assert!(generator.verify(&corrupt_payload).await.is_err());
    
    // Corrupt signature
    let corrupt_sig = format!("{}.{}.XXX{}", parts[0], parts[1], &parts[2][3..]);
    assert!(generator.verify(&corrupt_sig).await.is_err());
}

#[tokio::test]
async fn test_future_cancellation_safety() {
    let key = Hs256Key::random();
    let generator = Arc::new(Generator::new(key));
    
    // Test cancelling token generation
    let gen1 = generator.clone();
    let handle1 = tokio::spawn(async move {
        let claims = ClaimsBuilder::new()
            .subject("cancel_test")
            .expires_in(Duration::hours(1))
            .issued_now()
            .build();
        
        gen1.token(&claims).await
    });
    
    // Cancel the task
    handle1.abort();
    assert!(handle1.await.is_err());
    
    // Generator should still work
    let claims = ClaimsBuilder::new()
        .subject("after_cancel")
        .expires_in(Duration::hours(1))
        .issued_now()
        .build();
    
    let token = generator.token(&claims).await.unwrap();
    assert!(!token.is_empty());
}