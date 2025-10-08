use chrono::{Duration, Utc};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // JWT Example - demonstrating README.md patterns
    let _secret_key = b"my_secret_key_for_jwt_signing_123";

    // Create claims as JSON value
    let claims = serde_json::json!({
        "sub": "user123",
        "exp": (Utc::now() + Duration::hours(1)).timestamp(),
        "iat": Utc::now().timestamp()
    });

    println!("JWT Example - Demonstrating README.md API Patterns");
    println!("Claims: {}", claims);

    // The JWT API implementation is still in development
    // This example shows the intended patterns from README.md
    println!("\n=== Single JWT Pattern (from README.md) ===");
    println!("let jwt = Cryypt::jwt()");
    println!("    .hs256()");
    println!("    .with_secret(secret_key)");
    println!("    .with_claims(Claims::new()");
    println!("        .subject(\"user123\")");
    println!("        .expiration(Utc::now() + Duration::hours(1))");
    println!("    )");
    println!("    .on_result(|result| {{");
    println!("        Ok(jwt_bytes) => {{");
    println!("            let token = String::from_utf8(jwt_bytes.clone())");
    println!("                .map_err(|e| JwtError::InvalidEncoding(e.to_string()))?;");
    println!("            log::info!(\"JWT: {{}}\", token);");
    println!("            jwt_bytes.into()");
    println!("        }}");
    println!("        Err(e) => {{");
    println!("            log::error!(\"JWT signing failed: {{}}\", e);");
    println!("            panic!(\"Critical JWT signing failure\")");
    println!("        }}");
    println!("    }})");
    println!("    .sign()");
    println!("    .await;");

    println!("\n=== Batch JWT Pattern (from README.md) ===");
    println!("let mut stream = Cryypt::jwt()");
    println!("    .rs256()");
    println!("    .with_private_key(private_key)");
    println!("    .on_chunk(|result| {{");
    println!("        Ok(jwt_chunk) => {{");
    println!("            // Process batch of signed JWTs");
    println!("            distribute_tokens(&jwt_chunk);");
    println!("            jwt_chunk.into()");
    println!("        }}");
    println!("        Err(e) => {{");
    println!("            log::error!(\"JWT batch signing failed: {{}}\", e);");
    println!("            panic!(\"Critical JWT batch failure\")");
    println!("        }}");
    println!("    }})");
    println!("    .sign_batch(user_claims_list);");
    println!();
    println!("while let Some(jwt_batch) = stream.next().await {{");
    println!("    log::info!(\"Signed {{}} JWTs\", jwt_batch.len());");
    println!("}}");

    println!("\n=== Implementation Notes ===");
    println!("- JWT API follows the same on_result!/on_chunk! patterns as other modules");
    println!("- Actions take data as arguments: sign(claims) not with_claims().sign()");
    println!("- Error handling comes before action methods");
    println!("- Both single and streaming operations supported");
    println!("- API implementation may still be in development");

    println!("\nJWT example completed - patterns demonstrated");

    Ok(())
}
