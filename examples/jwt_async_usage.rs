//! Example demonstrating async JWT usage with concrete Future types.
//!
//! This example shows how to use the JWT library's async-friendly interface
//! that returns concrete Future types instead of using async functions.

use chrono::Duration;
use cryypt::jwt::{
    Claims, ClaimsBuilder, Es256Key, Generator, Hs256Key, Revocation, ValidationOptions,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("JWT Async Example - Concrete Future Types\n");

    // Example 1: Basic token generation and verification with HS256
    example_hs256_basic().await?;

    // Example 2: ES256 with custom validation
    example_es256_validation().await?;

    // Example 3: Token revocation
    example_revocation().await?;

    // Example 4: Parallel token operations
    example_parallel_operations().await?;

    Ok(())
}

async fn example_hs256_basic() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Example 1: Basic HS256 Token Generation ===");

    // Create a random HS256 key
    let key = Hs256Key::random().with_kid("test-key-1");

    // Create a generator
    let generator = Generator::new(key);

    // Build claims
    let claims = ClaimsBuilder::new()
        .subject("user123")
        .expires_in(Duration::hours(1))
        .issued_now()
        .issuer("my-app")
        .audience(vec!["api.example.com".to_string()])
        .claim("role".into(), serde_json::json!("admin"))
        .build();

    println!("Claims: {:?}", claims);

    // Generate token - returns a TokenGenerationFuture
    let token = generator.token(&claims).await?;
    println!("Generated token: {}", &token[..50]); // Show first 50 chars

    // Verify token - returns a TokenVerificationFuture
    let verified_claims = generator.verify(&token).await?;
    println!("Verified claims: {:?}", verified_claims);

    // Verify with a different token (should fail)
    let invalid_token = token.replace(".", "x");
    match generator.verify(invalid_token).await {
        Err(e) => println!("Expected error for invalid token: {}", e),
        Ok(_) => panic!("Should have failed!"),
    }

    println!();
    Ok(())
}

async fn example_es256_validation() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Example 2: ES256 with Custom Validation ===");

    // Create ES256 key
    let key = Es256Key::new().with_kid("es256-key-1");

    // Create generator with custom validation options
    let validation_opts = ValidationOptions {
        leeway: Duration::seconds(30),
        validate_exp: true,
        validate_nbf: true,
        required_claims: vec!["department".to_string()],
        allowed_algorithms: vec!["ES256"],
        expected_issuer: Some("secure-app".to_string()),
        expected_audience: Some(vec!["secure-api".to_string()]),
    };

    let generator = Generator::new(key).with_validation_options(validation_opts);

    // Build claims with all required fields
    let claims = ClaimsBuilder::new()
        .subject("user456")
        .expires_in(Duration::minutes(30))
        .issued_now()
        .not_before(chrono::Utc::now() - Duration::minutes(1))
        .issuer("secure-app")
        .audience(vec!["secure-api".to_string(), "backup-api".to_string()])
        .jwt_id("unique-jwt-id-123")
        .claim("department".into(), serde_json::json!("engineering"))
        .build();

    // Generate and verify
    let token = generator.token(&claims).await?;
    println!("ES256 token generated successfully");

    let verified = generator.verify(&token).await?;
    println!("Verified ES256 token for subject: {}", verified.sub);

    // Try without required claim (should fail)
    let incomplete_claims = ClaimsBuilder::new()
        .subject("user789")
        .expires_in(Duration::minutes(30))
        .issued_now()
        .issuer("secure-app")
        .audience(vec!["secure-api".to_string()])
        .build();

    let token2 = generator.token(&incomplete_claims).await?;
    match generator.verify(&token2).await {
        Err(e) => println!("Expected validation error: {}", e),
        Ok(_) => panic!("Should have failed validation!"),
    }

    println!();
    Ok(())
}

async fn example_revocation() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Example 3: Token Revocation ===");

    // Create revocation-wrapped signer
    let key = Hs256Key::random();
    let revocation = Revocation::wrap(key);

    // Start cleanup task (runs every 5 minutes)
    revocation.start_cleanup(Duration::minutes(5)).await;

    // Generate some tokens
    let claims = ClaimsBuilder::new()
        .subject("revoke-test")
        .expires_in(Duration::hours(2))
        .issued_now()
        .build();

    let token1 = revocation.token(&claims).await?;
    let token2 = revocation.token(&claims).await?;
    println!("Generated 2 tokens");

    // Verify both work
    let _ = revocation.verify(&token1).await?;
    let _ = revocation.verify(&token2).await?;
    println!("Both tokens verified successfully");

    // Revoke token1
    revocation.revoke(&token1, "User logged out");
    println!("Revoked token1");

    // Try to verify again
    match revocation.verify(&token1).await {
        Err(e) => println!("Token1 correctly rejected: {}", e),
        Ok(_) => panic!("Revoked token should fail!"),
    }

    // Token2 should still work
    let _ = revocation.verify(&token2).await?;
    println!("Token2 still valid");

    // Stop cleanup when done
    revocation.stop_cleanup().await;

    println!();
    Ok(())
}

async fn example_parallel_operations() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Example 4: Parallel Token Operations ===");

    let key = Es256Key::new();
    let generator = Generator::new(key);

    // Create multiple different claims
    let claims_list: Vec<Claims> = (0..5)
        .map(|i| {
            ClaimsBuilder::new()
                .subject(format!("user{}", i))
                .expires_in(Duration::hours(1))
                .issued_now()
                .claim("batch".into(), serde_json::json!(i))
                .build()
        })
        .collect();

    println!("Generating 5 tokens in parallel...");

    // Generate all tokens in parallel
    let token_futures: Vec<_> = claims_list
        .iter()
        .map(|claims| generator.token(claims))
        .collect();

    // Await all futures concurrently
    let tokens = futures::future::try_join_all(token_futures).await?;
    println!("Generated {} tokens", tokens.len());

    println!("Verifying all tokens in parallel...");

    // Verify all tokens in parallel
    let verify_futures: Vec<_> = tokens.iter().map(|token| generator.verify(token)).collect();

    let verified_claims = futures::future::try_join_all(verify_futures).await?;

    // Print subjects
    for claims in verified_claims {
        println!(
            "  Verified: {} (batch: {})",
            claims.sub, claims.extra["batch"]
        );
    }

    println!("\nParallel operations completed successfully!");
    Ok(())
}
