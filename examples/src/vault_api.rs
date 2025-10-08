//! Comprehensive CLI integration test using Process commands
//! Tests every vault CLI command with actual process execution

use serde_json::Value;
use std::process::Stdio;
use tokio::process::Command;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Vault CLI Integration Test ===");

    let vault_path = "/tmp/cli_test_vault.db";
    let passphrase = "test123";

    // Clean up any existing vault
    let _ = std::fs::remove_file(vault_path);

    println!("Testing CRUD operations...");
    test_crud_operations(vault_path, passphrase).await?;

    println!("Testing query operations...");
    test_query_operations(vault_path, passphrase).await?;

    println!("Testing passphrase operations...");
    test_passphrase_operations(vault_path).await?;

    println!("Testing key management...");
    test_key_management(vault_path, passphrase).await?;

    println!("Testing run command...");
    test_run_command(vault_path, passphrase).await?;

    println!("Testing save operations...");
    test_save_operations(vault_path, passphrase).await?;

    println!("Testing error conditions...");
    test_error_conditions(vault_path).await?;

    // Cleanup
    let _ = std::fs::remove_file(vault_path);

    println!("✅ ALL TESTS PASSED - Vault CLI fully functional");
    Ok(())
}

async fn test_crud_operations(
    vault_path: &str,
    passphrase: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // Test PUT operation (creates vault)
    let output = run_vault_json(vault_path, passphrase, &["put", "key1", "test value 1"]).await?;
    assert!(output["success"]
        .as_bool()
        .expect("PUT: success field missing"));
    assert_eq!(
        output["operation"]
            .as_str()
            .expect("PUT: operation missing"),
        "put"
    );
    assert_eq!(output["key"].as_str().expect("PUT: key missing"), "key1");

    // Test GET operation
    let output = run_vault_json(vault_path, passphrase, &["get", "key1"]).await?;
    assert!(output["success"]
        .as_bool()
        .expect("GET: success field missing"));
    assert_eq!(
        output["operation"]
            .as_str()
            .expect("GET: operation missing"),
        "get"
    );
    assert_eq!(
        output["value"].as_str().expect("GET: value missing"),
        "test value 1"
    );

    // Test PUT update existing key
    let output =
        run_vault_json(vault_path, passphrase, &["put", "key1", "updated value 1"]).await?;
    assert!(output["success"]
        .as_bool()
        .expect("PUT UPDATE: success field missing"));

    // Verify update worked
    let output = run_vault_json(vault_path, passphrase, &["get", "key1"]).await?;
    assert_eq!(
        output["value"]
            .as_str()
            .expect("GET UPDATED: value missing"),
        "updated value 1"
    );

    // Test multiple keys
    let output = run_vault_json(vault_path, passphrase, &["put", "key2", "test value 2"]).await?;
    assert!(output["success"]
        .as_bool()
        .expect("PUT key2: success field missing"));

    let output = run_vault_json(vault_path, passphrase, &["put", "key3", "test value 3"]).await?;
    assert!(output["success"]
        .as_bool()
        .expect("PUT key3: success field missing"));

    // Test DELETE operation
    let output = run_vault_json(vault_path, passphrase, &["delete", "key2"]).await?;
    assert!(output["success"]
        .as_bool()
        .expect("DELETE: success field missing"));
    assert_eq!(
        output["operation"]
            .as_str()
            .expect("DELETE: operation missing"),
        "delete"
    );

    // Verify delete worked (key should not be found)
    let output = run_vault_json(vault_path, passphrase, &["get", "key2"]).await?;
    assert!(!output["success"]
        .as_bool()
        .expect("GET DELETED: success field missing"));
    assert_eq!(
        output["error_code"]
            .as_str()
            .expect("GET DELETED: error_code missing"),
        "KEY_NOT_FOUND"
    );

    println!("  ✅ CRUD operations working correctly");
    Ok(())
}

async fn test_query_operations(
    vault_path: &str,
    passphrase: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // Test LIST operation
    let output = run_vault_json(vault_path, passphrase, &["list"]).await?;
    assert!(output["success"]
        .as_bool()
        .expect("LIST: success field missing"));
    assert_eq!(
        output["operation"]
            .as_str()
            .expect("LIST: operation missing"),
        "list"
    );

    let keys = output["keys"].as_array().expect("LIST: keys array missing");
    assert!(keys.len() >= 2); // Should have key1 and key3 at least
    assert!(keys.iter().any(|k| k.as_str() == Some("key1")));
    assert!(keys.iter().any(|k| k.as_str() == Some("key3")));

    // Test FIND operation with pattern
    let output = run_vault_json(vault_path, passphrase, &["find", "key"]).await?;
    assert!(output["success"]
        .as_bool()
        .expect("FIND: success field missing"));
    assert_eq!(
        output["operation"]
            .as_str()
            .expect("FIND: operation missing"),
        "find"
    );

    let entries = output["entries"]
        .as_array()
        .expect("FIND: entries array missing");
    assert!(entries.len() >= 2);

    // Test FIND with specific pattern
    let output = run_vault_json(vault_path, passphrase, &["find", "key1"]).await?;
    let entries = output["entries"]
        .as_array()
        .expect("FIND key1: entries array missing");
    assert_eq!(entries.len(), 1);
    assert_eq!(
        entries[0]["key"].as_str().expect("FIND key1: key missing"),
        "key1"
    );

    println!("  ✅ Query operations working correctly");
    Ok(())
}

async fn test_passphrase_operations(vault_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let old_pass = "test123";
    let new_pass = "newpass456";

    // Test ChangePassphrase operation
    let output = run_vault_json(
        vault_path,
        old_pass,
        &[
            "change-passphrase",
            "--old-passphrase",
            old_pass,
            "--new-passphrase",
            new_pass,
        ],
    )
    .await?;
    assert!(output["success"]
        .as_bool()
        .expect("CHANGE_PASSPHRASE: success field missing"));
    assert_eq!(
        output["operation"]
            .as_str()
            .expect("CHANGE_PASSPHRASE: operation missing"),
        "change_passphrase"
    );

    // Test that old passphrase no longer works
    let output = run_vault_json(vault_path, old_pass, &["get", "key1"]).await;
    match output {
        Ok(json) => {
            let success = json["success"].as_bool().unwrap_or(true);
            assert!(!success);
        }
        Err(_) => {
            // Expected error case - old passphrase should not work
            // Test passes - this is the expected behavior
        }
    }

    // Test that new passphrase works
    let output = run_vault_json(vault_path, new_pass, &["get", "key1"]).await?;
    assert!(output["success"]
        .as_bool()
        .expect("NEW_PASSPHRASE: success field missing"));
    assert_eq!(
        output["value"]
            .as_str()
            .expect("NEW_PASSPHRASE: value missing"),
        "updated value 1"
    );

    // Change back for remaining tests
    let output = run_vault_json(
        vault_path,
        new_pass,
        &[
            "change-passphrase",
            "--old-passphrase",
            new_pass,
            "--new-passphrase",
            old_pass,
        ],
    )
    .await?;
    assert!(output["success"]
        .as_bool()
        .expect("CHANGE_BACK: success field missing"));

    println!("  ✅ Passphrase operations working correctly");
    Ok(())
}
async fn test_key_management(
    vault_path: &str,
    passphrase: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // Test GenerateKey operation
    let output = run_vault_json(
        vault_path,
        passphrase,
        &[
            "generate-key",
            "--namespace",
            "test",
            "--version",
            "1",
            "--bits",
            "256",
            "--store",
            "memory",
        ],
    )
    .await?;
    assert!(output["success"]
        .as_bool()
        .expect("GENERATE_KEY: success field missing"));
    assert_eq!(
        output["operation"]
            .as_str()
            .expect("GENERATE_KEY: operation missing"),
        "generate_key"
    );

    // Test RetrieveKey operation
    let output = run_vault_json(
        vault_path,
        passphrase,
        &[
            "retrieve-key",
            "--namespace",
            "test",
            "--version",
            "1",
            "--store",
            "memory",
        ],
    )
    .await?;
    assert!(output["success"]
        .as_bool()
        .expect("RETRIEVE_KEY: success field missing"));
    assert_eq!(
        output["operation"]
            .as_str()
            .expect("RETRIEVE_KEY: operation missing"),
        "retrieve_key"
    );

    // Test BatchGenerateKeys operation
    let output = run_vault_json(
        vault_path,
        passphrase,
        &[
            "batch-generate-keys",
            "--namespace",
            "batch",
            "--version",
            "1",
            "--count",
            "3",
            "--store",
            "memory",
        ],
    )
    .await?;
    assert!(output["success"]
        .as_bool()
        .expect("BATCH_GENERATE: success field missing"));
    assert_eq!(
        output["operation"]
            .as_str()
            .expect("BATCH_GENERATE: operation missing"),
        "batch_generate_keys"
    );

    println!("  ✅ Key management operations working correctly");
    Ok(())
}

async fn test_run_command(
    vault_path: &str,
    passphrase: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // Add some keys for environment testing
    let _ = run_vault_json(vault_path, passphrase, &["put", "api_key", "secret123"]).await?;
    let _ = run_vault_json(vault_path, passphrase, &["put", "db_host", "localhost"]).await?;

    // Test Run operation (run echo to verify environment variables)
    let output = run_vault_json(
        vault_path,
        passphrase,
        &["run", "echo", "VAULT_API_KEY=$VAULT_API_KEY"],
    )
    .await?;
    assert!(output["success"]
        .as_bool()
        .expect("RUN: success field missing"));
    assert_eq!(
        output["operation"]
            .as_str()
            .expect("RUN: operation missing"),
        "run"
    );

    let env_vars = output["env_vars"]
        .as_array()
        .expect("RUN: env_vars missing");
    assert!(env_vars.iter().any(|v| v.as_str() == Some("VAULT_API_KEY")));
    assert!(env_vars.iter().any(|v| v.as_str() == Some("VAULT_DB_HOST")));

    println!("  ✅ Run command working correctly");
    Ok(())
}

async fn test_save_operations(
    vault_path: &str,
    passphrase: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // Test Save operation
    let output = run_vault_json(vault_path, passphrase, &["save"]).await?;
    assert!(output["success"]
        .as_bool()
        .expect("SAVE: success field missing"));
    assert_eq!(
        output["operation"]
            .as_str()
            .expect("SAVE: operation missing"),
        "save"
    );

    println!("  ✅ Save operations working correctly");
    Ok(())
}

async fn test_error_conditions(vault_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    // Test wrong passphrase
    let result = run_vault_json(vault_path, "wrongpassword", &["get", "key1"]).await;
    match result {
        Ok(json) => {
            let success = json["success"].as_bool().unwrap_or(true);
            assert!(!success, "Wrong passphrase should fail");
        }
        Err(_) => {
            // Expected error case - wrong passphrase should fail
            // Test passes - this is the expected behavior
        }
    }

    // Test non-existent key
    let output = run_vault_json(vault_path, "test123", &["get", "nonexistent"]).await?;
    assert!(!output["success"]
        .as_bool()
        .expect("NONEXISTENT: success field missing"));
    assert_eq!(
        output["error_code"]
            .as_str()
            .expect("NONEXISTENT: error_code missing"),
        "KEY_NOT_FOUND"
    );

    println!("  ✅ Error conditions handled correctly");
    Ok(())
}

async fn run_vault_json(
    vault_path: &str,
    passphrase: &str,
    args: &[&str],
) -> Result<Value, Box<dyn std::error::Error>> {
    let mut cmd = Command::new("cargo");
    cmd.arg("run")
        .arg("--package")
        .arg("cryypt_vault")
        .arg("--");
    cmd.arg("--vault-path").arg(vault_path);
    cmd.arg("--passphrase").arg(passphrase);
    cmd.arg("--json");
    cmd.args(args);
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    let output = cmd.output().await?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("Command failed: {}", stderr).into());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: Value = serde_json::from_str(&stdout)?;
    Ok(json)
}
