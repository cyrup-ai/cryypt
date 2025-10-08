use cryypt_vault::config::{KeychainConfig, VaultConfig};
use cryypt_vault::core::VaultValue;
use cryypt_vault::db::vault_store::LocalVaultProvider;
use cryypt_vault::operation::{Passphrase, VaultOperation};
use std::path::PathBuf;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Testing vault core functionality...");

    let vault_path = PathBuf::from("/tmp/vault_test/core_test.db");
    
    let config = VaultConfig {
        vault_path: vault_path.clone(),
        keychain_config: KeychainConfig {
            app_name: "vault".to_string(),
            pq_namespace: "test_pqcrypto".to_string(),
            auto_generate: true,
        },
        ..Default::default()
    };

    println!("Creating vault provider...");
    let provider = LocalVaultProvider::new(config).await?;

    println!("Unlocking vault with test passphrase...");
    let passphrase = Passphrase::from("test_passphrase".to_string());
    let unlock_request = provider.unlock(&passphrase);
    unlock_request.await?;

    println!("✅ Vault unlocked successfully!");

    println!("Testing PUT operation...");
    provider
        .put(
            "test_key",
            &VaultValue::from_string("test_value".to_string()),
        )
        .await?;
    println!("✅ PUT operation successful!");

    println!("Testing GET operation...");
    let result = provider.get("test_key").await?;
    if let Some(value) = result {
        println!("✅ GET operation successful! Value: {:?}", value);
    } else {
        println!("❌ GET operation failed - no value found");
    }

    println!("Testing LIST operation...");
    let keys = provider.list(None).await?;
    println!("✅ LIST operation successful! Keys: {:?}", keys);

    println!("All core operations completed successfully!");
    Ok(())
}
