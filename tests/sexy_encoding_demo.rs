//! Demo of the sexy encoding builder API

use cryypt::prelude::*;

#[tokio::test]
async fn demo_sexy_encoding_api() -> Result<(), Box<dyn std::error::Error>> {
    let master_key = [42u8; 32];
    std::fs::create_dir_all("/tmp/sexy_demo").ok();

    println!("🚀 Demonstrating the sexy encoding API!");

    // 1. Encrypt and get base64 in one fluent chain
    println!("\n📦 Encrypt → Base64:");
    let base64_result = Cipher::aes()
        .with_key(
            Key::size(256.bits())
                .with_store(FileKeyStore::at("/tmp/sexy_demo").with_master_key(master_key))
                .with_namespace("demo")
                .version(1),
        )
        .with_text("Hello, sexy API! 🔥")
        .encrypt()
        .await?
        .to_base64();
    println!("   Result: {}", base64_result);

    // 2. Decrypt from base64
    println!("\n🔓 Decrypt from Base64:");
    let plaintext = Cipher::aes()
        .with_key(
            Key::size(256.bits())
                .with_store(FileKeyStore::at("/tmp/sexy_demo").with_master_key(master_key))
                .with_namespace("demo")
                .version(1),
        )
        .with_ciphertext_base64(&base64_result)?
        .decrypt()
        .await?;
    let text = String::from_utf8(plaintext)?;
    println!("   Decrypted: {}", text);

    // 3. Encrypt and get hex
    println!("\n🔢 Encrypt → Hex:");
    let hex_result = Cipher::aes()
        .with_key(
            Key::size(256.bits())
                .with_store(FileKeyStore::at("/tmp/sexy_demo").with_master_key(master_key))
                .with_namespace("demo")
                .version(2),
        )
        .with_data(b"Binary data \x00\x01\x02\xFF")
        .encrypt()
        .await?
        .to_hex();
    println!("   Result: {}", hex_result);

    // 4. File encryption workflow
    println!("\n📁 File Encryption Workflow:");
    let input_file = "/tmp/sexy_demo/secret.txt";
    let encrypted_file = "/tmp/sexy_demo/secret.enc";

    std::fs::write(input_file, "Super secret file contents! 🔒")?;

    // Encrypt file → save to file
    Cipher::aes()
        .with_key(
            Key::size(256.bits())
                .with_store(FileKeyStore::at("/tmp/sexy_demo").with_master_key(master_key))
                .with_namespace("demo")
                .version(3),
        )
        .with_file(input_file)
        .await?
        .encrypt()
        .await?
        .to_file(encrypted_file)
        .await?;

    println!("   ✅ File encrypted and saved!");

    // Decrypt file → get as string
    let decrypted_content = Cipher::aes()
        .with_key(
            Key::size(256.bits())
                .with_store(FileKeyStore::at("/tmp/sexy_demo").with_master_key(master_key))
                .with_namespace("demo")
                .version(3),
        )
        .with_ciphertext_file(encrypted_file)
        .await?
        .decrypt()
        .await?;

    let content = String::from_utf8(decrypted_content)?;
    println!("   Decrypted content: {}", content);

    // 5. Data from encoded input
    println!("\n🎯 Data from Encoded Input:");
    let hex_data = hex::encode(b"Data from hex!");
    let encrypted_result = Cipher::aes()
        .with_key(
            Key::size(256.bits())
                .with_store(FileKeyStore::at("/tmp/sexy_demo").with_master_key(master_key))
                .with_namespace("demo")
                .version(4),
        )
        .with_data_hex(&hex_data)?
        .encrypt()
        .await?;

    println!(
        "   ✅ Encrypted data from hex input, size: {} bytes",
        encrypted_result.len()
    );

    // 6. Compression + Encoding combo
    println!("\n🗜️ Compression + Encoding Combo:");
    let compressed_base64 = Cipher::aes()
        .with_key(
            Key::size(256.bits())
                .with_store(FileKeyStore::at("/tmp/sexy_demo").with_master_key(master_key))
                .with_namespace("demo")
                .version(5),
        )
        .with_compression(Compress::zstd())
        .with_text(&"This text will be compressed then encrypted then base64 encoded! ".repeat(10))
        .encrypt()
        .await?
        .to_base64();

    println!(
        "   Compressed+Encrypted+Base64 size: {}",
        compressed_base64.len()
    );

    // Cleanup
    std::fs::remove_dir_all("/tmp/sexy_demo").ok();

    println!("\n🎉 All sexy encoding features working perfectly!");
    Ok(())
}
