use cryypt_pqcrypto::{PqCryptoMasterBuilder, SecurityLevel};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let output_file = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "test_keypair.bin".to_string());

    println!("Generating PQCrypto keypair...");

    let keypair = PqCryptoMasterBuilder::new()
        .kyber()
        .with_security_level(SecurityLevel::Level3)
        .on_result(|result| match result {
            Ok(keypair) => keypair,
            Err(e) => {
                eprintln!("Failed to generate keypair: {}", e);
                std::process::exit(1);
            }
        })
        .generate_keypair()
        .await;

    tokio::fs::write(&output_file, &keypair).await?;
    println!("✅ Keypair saved to: {}", output_file);
    println!("   Size: {} bytes", keypair.len());

    Ok(())
}
