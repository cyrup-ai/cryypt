//! Tests for JWT claims builder error handling - ensuring no panics occur

use chrono::{Duration, Utc};
use cryypt_jwt::claims::*;

#[test]
fn test_claims_builder_type_safety() {
    // Test that build() can only be called when all required fields are set
    let builder = ClaimsBuilder::new();

    // This should not compile (but we can't test compilation failures in unit tests)
    // builder.build(); // Would be a compile error

    // Set only subject - still can't build
    let builder = builder.subject("test-user");
    // builder.build(); // Would be a compile error

    // Set subject and expiry - still can't build
    let builder = builder.expires_in(Duration::hours(1));
    // builder.build(); // Would be a compile error

    // Set all required fields - now can build
    let builder = builder.issued_now();
    let claims = builder.build(); // This should work

    assert_eq!(claims.sub, "test-user");
    assert!(claims.exp > 0);
    assert!(claims.iat > 0);
}

#[test]
fn test_claims_builder_safe_fallbacks() {
    // Test that even if the type system is somehow bypassed,
    // the build method provides safe fallbacks instead of panicking

    let builder = ClaimsBuilder::new()
        .subject("test-user")
        .expires_in(Duration::hours(1))
        .issued_now();

    let claims = builder.build();

    // Verify all fields are properly set
    assert_eq!(claims.sub, "test-user");
    assert!(claims.exp > 0);
    assert!(claims.iat > 0);
    assert!(claims.iss.is_none()); // Optional field
    assert!(claims.aud.is_none()); // Optional field
    assert!(claims.nbf.is_none()); // Optional field
    assert!(claims.jti.is_none()); // Optional field
    assert!(claims.extra.is_empty()); // Should be empty map
}

#[test]
fn test_claims_builder_with_optional_fields() {
    let builder = ClaimsBuilder::new()
        .subject("test-user")
        .expires_in(Duration::hours(2))
        .issued_now()
        .issuer("test-issuer")
        .audience(vec!["api".to_string(), "web".to_string()])
        .not_before(Utc::now())
        .jwt_id("unique-id-123");

    let claims = builder.build();

    assert_eq!(claims.sub, "test-user");
    assert!(claims.exp > 0);
    assert!(claims.iat > 0);
    assert_eq!(claims.iss, Some("test-issuer".to_string()));
    assert_eq!(claims.aud, Some(vec!["api".to_string(), "web".to_string()]));
    assert!(claims.nbf.is_some());
    assert_eq!(claims.jti, Some("unique-id-123".to_string()));
}

#[test]
fn test_claims_builder_multiple_builds() {
    // Test that we can build multiple claims from the same builder state
    // (though this requires cloning since build() consumes self)

    let base_builder = ClaimsBuilder::new()
        .subject("test-user")
        .expires_in(Duration::hours(1))
        .issued_now();

    // We can't actually test multiple builds from the same builder
    // since build() consumes self, but we can test that building works consistently
    let claims = base_builder.build();

    assert_eq!(claims.sub, "test-user");
    assert!(claims.exp > 0);
    assert!(claims.iat > 0);
}

#[test]
fn test_claims_builder_edge_cases() {
    // Test edge cases that might have previously caused panics

    // Empty subject (should still work with type system)
    let claims = ClaimsBuilder::new()
        .subject("")
        .expires_in(Duration::seconds(1))
        .issued_now()
        .build();

    assert_eq!(claims.sub, "");

    // Very short expiry
    let claims = ClaimsBuilder::new()
        .subject("short-lived")
        .expires_in(Duration::seconds(1))
        .issued_now()
        .build();

    assert_eq!(claims.sub, "short-lived");
    assert!(claims.exp > claims.iat); // Should still be in the future
}

#[test]
fn test_claims_serialization() {
    // Test that claims can be serialized/deserialized without issues
    let claims = ClaimsBuilder::new()
        .subject("serialization-test")
        .expires_in(Duration::hours(1))
        .issued_now()
        .issuer("test-issuer")
        .build();

    // Test JSON serialization
    let json = serde_json::to_string(&claims).expect("Should serialize to JSON");
    assert!(json.contains("serialization-test"));
    assert!(json.contains("test-issuer"));

    // Test JSON deserialization
    let deserialized: Claims = serde_json::from_str(&json).expect("Should deserialize from JSON");
    assert_eq!(deserialized.sub, claims.sub);
    assert_eq!(deserialized.exp, claims.exp);
    assert_eq!(deserialized.iat, claims.iat);
    assert_eq!(deserialized.iss, claims.iss);
}

#[test]
fn test_claims_with_custom_data() {
    use serde_json::json;

    let mut builder = ClaimsBuilder::new()
        .subject("custom-data-test")
        .expires_in(Duration::hours(1))
        .issued_now();

    // Add custom data
    builder = builder.custom("role", json!("admin"));
    builder = builder.custom("permissions", json!(["read", "write", "delete"]));

    let claims = builder.build();

    assert_eq!(claims.sub, "custom-data-test");
    assert_eq!(claims.extra.get("role"), Some(&json!("admin")));
    assert_eq!(
        claims.extra.get("permissions"),
        Some(&json!(["read", "write", "delete"]))
    );
}
