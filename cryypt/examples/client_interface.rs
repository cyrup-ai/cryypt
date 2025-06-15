//! CLIENT INTERFACE DEMONSTRATION
//! This shows exactly what users should be able to do based on README.md

use cryypt::prelude::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async_main())
}

async fn async_main() -> Result<(), Box<dyn std::error::Error>> {
    let master_key = [1u8; 32];

    println!("=== Testing Client Interface ===");

    // This is what README.md shows - IT SHOULD WORK
    let ciphertext = Cipher::aes()
        .with_key(Key::size(256u32.bits())
            .with_store(FileKeyStore::at("./keys").with_master_key(master_key))
            .with_namespace("my-app")
            .version(1))
        .with_data(b"Hello, World!")
        .encrypt()
        .await?;

    println!("Encryption successful!");

    let plaintext = Cipher::aes()
        .with_key(Key::size(256u32.bits())
            .with_store(FileKeyStore::at("./keys").with_master_key(master_key))
            .with_namespace("my-app")
            .version(1))
        .with_ciphertext(ciphertext)
        .decrypt()
        .await?;

    println!("Decryption successful!");
    assert_eq!(plaintext, b"Hello, World!");

    Ok(())
}