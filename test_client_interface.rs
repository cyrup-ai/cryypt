// CLIENT INTERFACE TEST - What users see in the README
// This should compile and work when the trait issues are fixed

use cryypt::{Cipher, Key, FileKeyStore, Hash, Compress};
use cryypt::compression::Compress as CompressAlias; // Alternative import style

async fn client_interface_examples() -> Result<(), Box<dyn std::error::Error>> {
    let master_key = [1u8; 32];

    // === 1. BASIC ENCRYPTION ===
    println!("=== Basic AES Encryption ===");
    let ciphertext = Cipher::aes()
        .with_key(Key::size(256.bits())
            .with_store(FileKeyStore::at("/secure/keys").with_master_key(master_key))
            .with_namespace("my-app")
            .version(1))
        .with_data(b"Hello, World!")
        .encrypt()
        .await?;

    let plaintext = Cipher::aes()
        .with_key(Key::size(256.bits())
            .with_store(FileKeyStore::at("/secure/keys").with_master_key(master_key))
            .with_namespace("my-app")
            .version(1))
        .with_ciphertext(ciphertext)
        .decrypt()
        .await?;

    assert_eq!(plaintext, b"Hello, World!");

    // === 2. CHACHA20 ENCRYPTION ===
    println!("=== ChaCha20 Encryption ===");
    let ciphertext = Cipher::chachapoly()
        .with_key(Key::size(256.bits())
            .with_store(FileKeyStore::at("/secure/keys").with_master_key(master_key))
            .with_namespace("secure-app")
            .version(1))
        .with_data(b"Secret message")
        .encrypt()
        .await?;

    // === 3. HASHING ===
    println!("=== Hashing ===");
    let hash = Hash::sha256()
        .with_data(b"Hello, World!")
        .hash()
        .await?;

    let hash_with_salt = Hash::sha256()
        .with_data(b"password")
        .with_salt(b"random_salt")
        .hash()
        .await?;

    let blake_hash = Hash::blake2b()
        .with_data(b"Hello, World!")
        .hash()
        .await?;

    // === 4. COMPRESSION ===
    println!("=== Compression ===");
    let compressed = Compress::zstd()
        .with_data(b"Large text that compresses well...")
        .compress()
        .await?;

    let original = Compress::zstd()
        .with_data(compressed)
        .decompress()
        .await?;

    // === 5. ENCRYPTION + COMPRESSION ===
    println!("=== Encryption + Compression ===");
    let result = Cipher::aes()
        .with_key(Key::size(256.bits())
            .with_store(FileKeyStore::at("/secure/keys").with_master_key(master_key))
            .with_namespace("app")
            .version(1))
        .with_compression(Compress::zstd())
        .with_data(b"Large sensitive data that compresses well...")
        .encrypt()
        .await?;

    let original = Cipher::aes()
        .with_key(Key::size(256.bits())
            .with_store(FileKeyStore::at("/secure/keys").with_master_key(master_key))
            .with_namespace("app")
            .version(1))
        .with_compression(Compress::zstd())
        .with_ciphertext(result)
        .decrypt()
        .await?;

    // === 6. TWO-PASS ENCRYPTION ===
    println!("=== Two-Pass Encryption ===");
    let ciphertext = Cipher::aes()
        .with_key(Key::size(256.bits())
            .with_store(FileKeyStore::at("/secure/keys").with_master_key(master_key))
            .with_namespace("app")
            .version(1))
        .with_data(b"Top secret")
        .second_pass(Cipher::chachapoly()
            .with_key(Key::size(256.bits())
                .with_store(FileKeyStore::at("/secure/keys").with_master_key(master_key))
                .with_namespace("app")
                .version(2)))
        .encrypt()
        .await?;

    // === 7. ENCODING OUTPUTS ===
    println!("=== Encoding Outputs ===");
    let encrypted_result = Cipher::aes()
        .with_key(Key::size(256.bits())
            .with_store(FileKeyStore::at("/secure/keys").with_master_key(master_key))
            .with_namespace("app")
            .version(1))
        .with_text("Secret message")
        .encrypt()
        .await?;

    let base64 = encrypted_result.to_base64();
    let hex = encrypted_result.to_hex();
    let bytes = encrypted_result.to_bytes();

    // === 8. INPUT FROM VARIOUS SOURCES ===
    println!("=== Various Input Sources ===");
    let ciphertext = Cipher::aes()
        .with_key(Key::size(256.bits())
            .with_store(FileKeyStore::at("/secure/keys").with_master_key(master_key))
            .with_namespace("app")
            .version(1))
        .with_data_base64("SGVsbG8gV29ybGQ=")?  // "Hello World" in base64
        .encrypt()
        .await?;

    let ciphertext2 = Cipher::aes()
        .with_key(Key::size(256.bits())
            .with_store(FileKeyStore::at("/secure/keys").with_master_key(master_key))
            .with_namespace("app")
            .version(1))
        .with_data_hex("48656c6c6f20576f726c64")?  // "Hello World" in hex
        .encrypt()
        .await?;

    println!("All client interface examples completed successfully!");
    Ok(())
}

// WHAT NEEDS TO WORK FOR CLIENT:
// 
// 1. `Key::size(256.bits())` returns something that can chain
// 2. `.with_store(FileKeyStore::at(...))` continues the chain
// 3. `.with_namespace(...)` continues the chain  
// 4. `.version(1)` returns something that `Cipher::aes().with_key(...)` accepts
// 5. All builder methods are discoverable via autocomplete
// 6. Error messages are clear when wrong features are enabled
// 7. Documentation shows which features enable which methods
//
// CURRENT ISSUE:
// The final type from Key builder chain doesn't implement KeyProviderBuilder
// that Cipher expects. This breaks the entire intended API.