//! JWT API examples - EXACTLY matching jwt/README.md

use cryypt::{Cryypt, on_result};
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    name: String,
    admin: bool,
}

/// JWT Creation and Verification example from README
async fn jwt_example() -> Result<(), Box<dyn std::error::Error>> {
    // Create custom claims
    let claims = Claims {
        sub: "1234567890".to_string(),
        name: "John Doe".to_string(),
        admin: true,
    };

    // Create and sign JWT
    let jwt = Cryypt::jwt()
        .hs256()
        .with_secret(b"your-256-bit-secret")
        .with_claims(claims)
        .with_expiry(Duration::from_secs(3600))
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("JWT creation error: {}", e))
        })
        .sign()
        .await; // Returns fully unwrapped value - no Result wrapper

    println!("JWT: {}", jwt);

    // Verify and decode JWT
    let decoded: Claims = Cryypt::jwt()
        .hs256()
        .with_secret(b"your-256-bit-secret")
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("JWT verification error: {}", e))
        })
        .verify(&jwt)
        .await; // Returns fully unwrapped value - no Result wrapper

    println!("Decoded claims: {:?}", decoded);

    // Use ES256 (elliptic curve)
    let (private_key, public_key) = Cryypt::jwt()
        .es256()
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("Key generation error: {}", e))
        })
        .generate_keys()
        .await; // Returns fully unwrapped value - no Result wrapper

    let jwt = Cryypt::jwt()
        .es256()
        .with_private_key(&private_key)
        .with_claims(claims)
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("JWT creation error: {}", e))
        })
        .sign()
        .await; // Returns fully unwrapped value - no Result wrapper

    let decoded: Claims = Cryypt::jwt()
        .es256()
        .with_public_key(&public_key)
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("JWT verification error: {}", e))
        })
        .verify(&jwt)
        .await; // Returns fully unwrapped value - no Result wrapper

    println!("ES256 decoded claims: {:?}", decoded);

    Ok(())
}

/// JWT with Standard Claims example from README
async fn standard_claims_example() -> Result<(), Box<dyn std::error::Error>> {
    use chrono::{Duration, Utc};
    
    #[derive(Debug, Serialize, Deserialize)]
    struct StandardClaims {
        sub: String,          // Subject
        aud: String,          // Audience  
        exp: i64,             // Expiration time
        nbf: i64,             // Not before
        iat: i64,             // Issued at
        iss: String,          // Issuer
        jti: String,          // JWT ID
        // Custom claims
        roles: Vec<String>,
        email: String,
    }
    
    let now = Utc::now();
    let claims = StandardClaims {
        sub: "user123".to_string(),
        aud: "my-app".to_string(),
        exp: (now + Duration::hours(1)).timestamp(),
        nbf: now.timestamp(),
        iat: now.timestamp(),
        iss: "auth-service".to_string(),
        jti: uuid::Uuid::new_v4().to_string(),
        roles: vec!["user".to_string(), "admin".to_string()],
        email: "user@example.com".to_string(),
    };
    
    let jwt = Cryypt::jwt()
        .hs256()
        .with_secret(b"your-256-bit-secret")
        .with_claims(claims)
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("JWT creation error: {}", e))
        })
        .sign()
        .await; // Returns fully unwrapped value - no Result wrapper
    
    println!("JWT with standard claims: {}", jwt);
    Ok(())
}

/// JWT Key Rotation example from README
async fn key_rotation_example() -> Result<(), Box<dyn std::error::Error>> {
    use cryypt::{Cryypt, on_result};
    
    // Generate multiple key versions
    let (private_key_v1, public_key_v1) = Cryypt::jwt()
        .es256()
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("Key generation error: {}", e))
        })
        .generate_keys()
        .await; // Returns fully unwrapped value - no Result wrapper
    
    let (private_key_v2, public_key_v2) = Cryypt::jwt()
        .es256()
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("Key generation error: {}", e))
        })
        .generate_keys()
        .await; // Returns fully unwrapped value - no Result wrapper
    
    // Create JWT rotation service
    let rotator = Cryypt::jwt()
        .rotator()
        .add_key("v1", public_key_v1)
        .add_key("v2", public_key_v2)
        .with_current_key("v2", private_key_v2)
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("Rotator creation error: {}", e))
        })
        .build()
        .await; // Returns fully unwrapped value - no Result wrapper
    
    // Sign with current key (v2)
    let jwt = rotator
        .sign(Claims {
            sub: "user123".to_string(),
            name: "Test User".to_string(),
            admin: false,
        })
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("JWT signing error: {}", e))
        })
        .await; // Returns fully unwrapped value - no Result wrapper
    
    // Verify (automatically tries all keys)
    let decoded: Claims = rotator
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("JWT verification error: {}", e))
        })
        .verify(&jwt)
        .await; // Returns fully unwrapped value - no Result wrapper
    
    println!("Decoded with key rotation: {:?}", decoded);
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Basic JWT Creation and Verification ===");
    jwt_example().await?;
    
    println!("\n=== JWT with Standard Claims ===");
    standard_claims_example().await?;
    
    println!("\n=== JWT Key Rotation ===");
    key_rotation_example().await?;
    
    Ok(())
}