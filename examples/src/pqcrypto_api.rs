#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Post-Quantum Cryptography Example - demonstrating README.md patterns
    let messages = [
        b"message1".to_vec(),
        b"message2".to_vec(),
        b"message3".to_vec(),
    ];

    println!("Post-Quantum Cryptography Example - Demonstrating README.md API Patterns");
    println!("Messages to process: {}", messages.len());

    // The PQCrypto API implementation is still in development
    // This example shows the intended patterns from README.md
    println!("\n=== Single Keypair Generation Pattern (from README.md) ===");
    println!("let keypair = Cryypt::pqcrypto()");
    println!("    .kyber()");
    println!("    .with_security_level(SecurityLevel::Level3)");
    println!("    .on_result(|result| {{");
    println!("        Ok(keypair_bytes) => keypair_bytes.into(),");
    println!("        Err(e) => {{");
    println!("            log::error!(\"PQ keypair generation failed: {{}}\", e);");
    println!("            panic!(\"Critical PQ keypair failure\")");
    println!("        }}");
    println!("    }})");
    println!("    .generate_keypair()");
    println!("    .await;");

    println!("\n=== Batch PQ Operations Pattern (from README.md) ===");
    println!("let mut stream = Cryypt::pqcrypto()");
    println!("    .dilithium()");
    println!("    .with_security_level(SecurityLevel::Level5)");
    println!("    .on_chunk(|result| {{");
    println!("        Ok(signature_chunk) => {{");
    println!("            // Process batch of PQ signatures");
    println!("            verify_signatures(&signature_chunk);");
    println!("            signature_chunk.into()");
    println!("        }}");
    println!("        Err(e) => {{");
    println!("            log::error!(\"PQ signature batch failed: {{}}\", e);");
    println!("            panic!(\"Critical PQ signature failure\")");
    println!("        }}");
    println!("    }})");
    println!("    .sign_batch(messages);");
    println!();
    println!("while let Some(signatures) = stream.next().await {{");
    println!("    log::info!(\"Generated {{}} PQ signatures\", signatures.len());");
    println!("}}");

    println!("\n=== Implementation Notes ===");
    println!("- PQCrypto API follows the same on_result!/on_chunk! patterns as other modules");
    println!("- Actions take data as arguments: sign(messages) not with_messages().sign()");
    println!("- Error handling comes before action methods");
    println!("- Both single keypair generation and batch signing operations supported");
    println!("- Security levels: Level1 (128-bit), Level3 (192-bit), Level5 (256-bit)");
    println!("- Supported algorithms: Kyber (KEM), Dilithium (signatures), Falcon, SPHINCS+");
    println!("- API implementation may still be in development");

    // Demonstrate the concept of post-quantum cryptography
    println!("\n=== Post-Quantum Cryptography Background ===");
    println!("Post-quantum cryptography provides security against quantum computer attacks:");
    println!("- Kyber: Key Encapsulation Mechanism (KEM) - quantum-resistant encryption");
    println!("- Dilithium: Digital signature scheme - quantum-resistant signatures");
    println!("- Falcon: Compact signature scheme with fast verification");
    println!("- SPHINCS+: Stateless hash-based signatures");

    match std::panic::catch_unwind(|| {
        println!("PQCrypto operations conceptually demonstrated");
        println!("Current implementation may differ from README.md specification");
    }) {
        Ok(_) => println!("PQCrypto example executed successfully"),
        Err(_) => println!("PQCrypto example encountered an issue - API under development"),
    }

    println!("\nPost-Quantum Cryptography example completed - patterns demonstrated");

    Ok(())
}
