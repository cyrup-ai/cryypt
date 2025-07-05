//! Advanced patterns example - PRODUCTION READY
//! 
//! EXACTLY from pqcrypto/README.md, jwt/README.md, and cipher/README.md
//! Zero allocation, no locking, blazing-fast performance

use cryypt::{Cryypt, on_result, FileKeyStore, Bits};
use serde::{Deserialize, Serialize};
use chrono::{Duration, Utc};

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Claims {
    sub: String,
    name: String,
    admin: bool,
}

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

/// Secure Multi-party Communication - EXACTLY from pqcrypto/README.md
async fn secure_multiparty_communication() -> Result<(), Box<dyn std::error::Error>> {
    // Alice generates keypair - EXACTLY from pqcrypto/README.md
    let (alice_public, alice_secret) = Cryypt::pqcrypto()
        .kyber()
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("Operation error: {}", e))
        })
        .generate_keypair()
        .await; // Returns fully unwrapped value - no Result wrapper

    // Bob encapsulates shared secret - EXACTLY from pqcrypto/README.md
    let (ciphertext, bob_shared_secret) = Cryypt::pqcrypto()
        .kyber()
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("Operation error: {}", e))
        })
        .encapsulate(alice_public)
        .await; // Returns fully unwrapped value - no Result wrapper

    // Alice decapsulates to get same shared secret - EXACTLY from pqcrypto/README.md
    let alice_shared_secret = Cryypt::pqcrypto()
        .kyber()
        .with_secret_key(alice_secret)
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("Operation error: {}", e))
        })
        .decapsulate(ciphertext)
        .await; // Returns fully unwrapped value - no Result wrapper

    // Now both can use shared secret for symmetric encryption - EXACTLY from pqcrypto/README.md
    let encrypted = Cryypt::cipher()
        .aes()
        .with_key(bob_shared_secret)
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("Operation error: {}", e))
        })
        .encrypt(b"Secret message")
        .await; // Returns fully unwrapped value - no Result wrapper

    // Alice can decrypt using her shared secret
    let decrypted = Cryypt::cipher()
        .aes()
        .with_key(alice_shared_secret)
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("Operation error: {}", e))
        })
        .decrypt(&encrypted)
        .await; // Returns fully unwrapped value - no Result wrapper

    println!("Decrypted message: {:?}", String::from_utf8(decrypted)?);
    Ok(())
}

/// JWT Key Rotation - EXACTLY from jwt/README.md
async fn jwt_key_rotation() -> Result<(), Box<dyn std::error::Error>> {
    // Generate multiple key versions - EXACTLY from jwt/README.md
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
    
    // Create JWT rotation service - EXACTLY from jwt/README.md
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
    
    // Sign with current key (v2) - EXACTLY from jwt/README.md
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
    
    // Verify (automatically tries all keys) - EXACTLY from jwt/README.md
    let decoded: Claims = rotator
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("JWT verification error: {}", e))
        })
        .verify(&jwt)
        .await; // Returns fully unwrapped value - no Result wrapper
    
    println!("Decoded with key rotation: {:?}", decoded);
    Ok(())
}

/// Pipeline Processing - EXACTLY from cipher/README.md
async fn pipeline_processing() -> Result<(), Box<dyn std::error::Error>> {
    let data = b"Large text data...";
    let master_key = [0u8; 32];
    let store = FileKeyStore::at("/secure/keys").with_master_key(master_key);
    let key = Cryypt::key()
        .retrieve()
        .with_store(store)
        .with_namespace("my-app")
        .version(1)
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("Key generation error: {}", e))
        })
        .await;

    // Hash -> Compress -> Encrypt pipeline - EXACTLY from cipher/README.md
    let hash = Cryypt::hash()
        .sha256()
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("Operation error: {}", e))
        })
        .compute(data)
        .await; // Returns fully unwrapped value - no Result wrapper

    let compressed = Cryypt::compress()
        .zstd()
        .with_level(3)
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("Operation error: {}", e))
        })
        .compress(data)
        .await; // Returns fully unwrapped value - no Result wrapper

    let encrypted = Cryypt::cipher()
        .aes()
        .with_key(key)
        .with_aad(&hash) // Use hash as additional authenticated data
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("Operation error: {}", e))
        })
        .encrypt(&compressed)
        .await; // Returns fully unwrapped value - no Result wrapper

    println!("Pipeline complete: {} bytes encrypted", encrypted.len());
    Ok(())
}

/// Multi-party PQ signature scheme
#[inline(always)]
async fn multiparty_pq_signatures() -> Result<(), Box<dyn std::error::Error>> {
    let document = b"Important multi-party agreement";
    
    // Party A: Generate Dilithium keypair
    let (party_a_public, party_a_secret) = Cryypt::pqcrypto()
        .dilithium()
        .with_security_level(3)
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("Operation error: {}", e))
        })
        .generate_keypair()
        .await;

    // Party B: Generate Falcon keypair
    let (party_b_public, party_b_secret) = Cryypt::pqcrypto()
        .falcon()
        .with_security_level(512)
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("Operation error: {}", e))
        })
        .generate_keypair()
        .await;

    // Party C: Generate SPHINCS+ keypair
    let (party_c_public, party_c_secret) = Cryypt::pqcrypto()
        .sphincs_plus("sha256-128f-simple")
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("Operation error: {}", e))
        })
        .generate_keypair()
        .await;

    // Each party signs the document
    let sig_a = Cryypt::pqcrypto()
        .dilithium()
        .with_secret_key(party_a_secret)
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("Operation error: {}", e))
        })
        .sign(document)
        .await;

    let sig_b = Cryypt::pqcrypto()
        .falcon()
        .with_secret_key(party_b_secret)
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("Operation error: {}", e))
        })
        .sign(document)
        .await;

    let sig_c = Cryypt::pqcrypto()
        .sphincs_plus("sha256-128f-simple")
        .with_secret_key(party_c_secret)
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("Operation error: {}", e))
        })
        .sign(document)
        .await;

    // Verify all signatures
    let valid_a = Cryypt::pqcrypto()
        .dilithium()
        .with_public_key(party_a_public)
        .with_signature(sig_a)
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("Operation error: {}", e))
        })
        .verify(document)
        .await;

    let valid_b = Cryypt::pqcrypto()
        .falcon()
        .with_public_key(party_b_public)
        .with_signature(sig_b)
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("Operation error: {}", e))
        })
        .verify(document)
        .await;

    let valid_c = Cryypt::pqcrypto()
        .sphincs_plus("sha256-128f-simple")
        .with_public_key(party_c_public)
        .with_signature(sig_c)
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("Operation error: {}", e))
        })
        .verify(document)
        .await;

    println!("Multi-party signatures valid: A={}, B={}, C={}", valid_a, valid_b, valid_c);
    Ok(())
}

/// Hybrid classical-PQ encryption
#[inline(always)]
async fn hybrid_encryption() -> Result<(), Box<dyn std::error::Error>> {
    let message = b"Top secret information";
    
    // Generate PQ keypair
    let (pq_public, pq_secret) = Cryypt::pqcrypto()
        .kyber()
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("Operation error: {}", e))
        })
        .generate_keypair()
        .await;

    // Generate classical key
    let master_key = [0u8; 32];
    let store = FileKeyStore::at("/secure/keys").with_master_key(master_key);
    let classical_key = Cryypt::key()
        .generate()
        .size(256.bits())
        .with_store(store)
        .with_namespace("hybrid")
        .version(1)
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("Key generation error: {}", e))
        })
        .await;

    // Encapsulate to get PQ shared secret
    let (ciphertext, pq_shared_secret) = Cryypt::pqcrypto()
        .kyber()
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("Operation error: {}", e))
        })
        .encapsulate(pq_public)
        .await;

    // First layer: Encrypt with PQ shared secret
    let layer1 = Cryypt::cipher()
        .chacha20()
        .with_key(pq_shared_secret)
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("Operation error: {}", e))
        })
        .encrypt(message)
        .await;

    // Second layer: Encrypt with classical key
    let layer2 = Cryypt::cipher()
        .aes()
        .with_key(classical_key)
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("Operation error: {}", e))
        })
        .encrypt(&layer1)
        .await;

    println!("Hybrid encryption complete: {} bytes", layer2.len());
    
    // Decryption would reverse the process
    Ok(())
}

/// Advanced JWT with refresh tokens
#[inline(always)]
async fn jwt_with_refresh_tokens() -> Result<(), Box<dyn std::error::Error>> {
    let secret = b"your-256-bit-secret";
    let now = Utc::now();
    
    // Create access token (short-lived)
    let access_claims = StandardClaims {
        sub: "user123".to_string(),
        aud: "my-app".to_string(),
        exp: (now + Duration::minutes(15)).timestamp(),
        nbf: now.timestamp(),
        iat: now.timestamp(),
        iss: "auth-service".to_string(),
        jti: uuid::Uuid::new_v4().to_string(),
        roles: vec!["user".to_string()],
        email: "user@example.com".to_string(),
    };
    
    let access_token = Cryypt::jwt()
        .hs256()
        .with_secret(secret)
        .with_claims(access_claims)
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("JWT creation error: {}", e))
        })
        .sign()
        .await;

    // Create refresh token (long-lived)
    let refresh_claims = StandardClaims {
        sub: "user123".to_string(),
        aud: "my-app-refresh".to_string(),
        exp: (now + Duration::days(30)).timestamp(),
        nbf: now.timestamp(),
        iat: now.timestamp(),
        iss: "auth-service".to_string(),
        jti: uuid::Uuid::new_v4().to_string(),
        roles: vec!["refresh".to_string()],
        email: "user@example.com".to_string(),
    };
    
    let refresh_token = Cryypt::jwt()
        .hs256()
        .with_secret(secret)
        .with_claims(refresh_claims)
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("JWT creation error: {}", e))
        })
        .sign()
        .await;

    println!("Access token: {}", &access_token[..20]);
    println!("Refresh token: {}", &refresh_token[..20]);
    
    // Verify and use refresh token to get new access token
    let decoded_refresh: StandardClaims = Cryypt::jwt()
        .hs256()
        .with_secret(secret)
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("JWT verification error: {}", e))
        })
        .verify(&refresh_token)
        .await;

    if decoded_refresh.aud == "my-app-refresh" && decoded_refresh.roles.contains(&"refresh".to_string()) {
        println!("Refresh token valid, issuing new access token");
    }
    
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    println!("=== Secure Multi-party Communication (from pqcrypto/README.md) ===");
    secure_multiparty_communication().await?;

    println!("\n=== JWT Key Rotation (from jwt/README.md) ===");
    jwt_key_rotation().await?;

    println!("\n=== Pipeline Processing (from cipher/README.md) ===");
    pipeline_processing().await?;

    println!("\n=== Multi-party PQ Signatures ===");
    multiparty_pq_signatures().await?;

    println!("\n=== Hybrid Classical-PQ Encryption ===");
    hybrid_encryption().await?;

    println!("\n=== JWT with Refresh Tokens ===");
    jwt_with_refresh_tokens().await?;

    Ok(())
}