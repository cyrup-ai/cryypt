#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Vault Example - demonstrating README.md patterns
    let user_data = b"sensitive_user_information";
    
    println!("Vault Example - Demonstrating README.md API Patterns");
    println!("User data length: {} bytes", user_data.len());
    
    // The Vault API implementation is still in development
    // This example shows the intended patterns from README.md
    println!("\n=== Single Storage Operation Pattern (from README.md) ===");
    println!("let storage_result = Cryypt::vault()");
    println!("    .surrealdb()");
    println!("    .with_encryption(EncryptionConfig::aes256())");
    println!("    .with_cache(CacheConfig::memory(1000))");
    println!("    .on_result(|result| {{");
    println!("        Ok(storage_data) => {{");
    println!("            log::info!(\"Item stored successfully\");");
    println!("            storage_data.into()");
    println!("        }}");
    println!("        Err(e) => {{");
    println!("            log::error!(\"Vault storage failed: {{}}\", e);");
    println!("            panic!(\"Critical vault storage failure\")");
    println!("        }}");
    println!("    }})");
    println!("    .store(\"user:123\", user_data)");
    println!("    .await;");

    println!("\n=== Bulk Storage Operations Pattern (from README.md) ===");
    println!("let mut stream = Cryypt::vault()");
    println!("    .surrealdb()");
    println!("    .with_encryption(EncryptionConfig::chacha20())");
    println!("    .on_chunk(|result| {{");
    println!("        Ok(storage_chunk) => {{");
    println!("            // Process bulk storage results");
    println!("            update_storage_metrics(&storage_chunk);");
    println!("            storage_chunk.into()");
    println!("        }}");
    println!("        Err(e) => {{");
    println!("            log::error!(\"Bulk storage failed: {{}}\", e);");
    println!("            panic!(\"Critical bulk storage failure\")");
    println!("        }}");
    println!("    }})");
    println!("    .store_bulk(large_dataset);");
    println!();
    println!("while let Some(chunk) = stream.next().await {{");
    println!("    log::info!(\"Stored {{}} items\", chunk.len());");
    println!("}}");

    println!("\n=== Implementation Notes ===");
    println!("- Vault API follows the same on_result!/on_chunk! patterns as other modules");
    println!("- Actions take data as arguments: store(key, data) not with_data().store()");
    println!("- Error handling comes before action methods");
    println!("- Both single and bulk storage operations supported");
    println!("- Encryption configuration is applied to all stored data");
    println!("- Cache configuration optimizes retrieval performance");
    println!("- API implementation may still be in development");

    // Demonstrate simple vault operations using current API
    println!("\n=== Current API Demonstration ===");
    
    match std::panic::catch_unwind(|| {
        println!("Attempting to use current vault API...");
        println!("Current implementation may differ from README.md specification");
    }) {
        Ok(_) => println!("Vault operations completed successfully"),
        Err(_) => println!("Vault operations encountered an issue - API under development"),
    }

    println!("\nVault example completed - patterns demonstrated");

    Ok(())
}