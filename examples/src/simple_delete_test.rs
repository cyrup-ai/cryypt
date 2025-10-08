#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Simple DELETE Test ===");

    // Test vault CLI directly with simple operations
    let vault_path = "./test_delete_vault.db";
    let passphrase = "test123";

    // Clean up any existing vault
    if std::fs::metadata(vault_path).is_ok() {
        std::fs::remove_file(vault_path)?;
    }

    // PUT a key
    println!("1. PUT key2 = 'test value 2'");
    let output = std::process::Command::new("cargo")
        .args([
            "run",
            "--package",
            "cryypt_vault",
            "--bin",
            "cryypt",
            "--",
            "--vault-path",
            vault_path,
            "--passphrase",
            passphrase,
            "put",
            "key2",
            "test value 2",
            "--json",
        ])
        .current_dir("/Volumes/samsung_t9/cryypt")
        .output()?;

    let put_result = String::from_utf8(output.stdout)?;
    let put_error = String::from_utf8(output.stderr)?;
    println!("PUT result: {}", put_result);
    if !put_error.is_empty() {
        println!("PUT error: {}", put_error);
    }

    // GET the key to verify it exists
    println!("\n2. GET key2 to verify it exists");
    let output = std::process::Command::new("cargo")
        .args([
            "run",
            "--package",
            "cryypt_vault",
            "--bin",
            "cryypt",
            "--",
            "--vault-path",
            vault_path,
            "--passphrase",
            passphrase,
            "get",
            "key2",
            "--json",
        ])
        .current_dir("/Volumes/samsung_t9/cryypt")
        .output()?;

    let get_result1 = String::from_utf8(output.stdout)?;
    println!("GET result (before delete): {}", get_result1);

    // DELETE the key
    println!("\n3. DELETE key2");
    let output = std::process::Command::new("cargo")
        .args([
            "run",
            "--package",
            "cryypt_vault",
            "--bin",
            "cryypt",
            "--",
            "--vault-path",
            vault_path,
            "--passphrase",
            passphrase,
            "delete",
            "key2",
            "--json",
        ])
        .current_dir("/Volumes/samsung_t9/cryypt")
        .output()?;

    let delete_result = String::from_utf8(output.stdout)?;
    println!("DELETE result: {}", delete_result);

    // GET the key again to see if it was deleted
    println!("\n4. GET key2 to verify it was deleted");
    let output = std::process::Command::new("cargo")
        .args([
            "run",
            "--package",
            "cryypt_vault",
            "--bin",
            "cryypt",
            "--",
            "--vault-path",
            vault_path,
            "--passphrase",
            passphrase,
            "get",
            "key2",
            "--json",
        ])
        .current_dir("/Volumes/samsung_t9/cryypt")
        .output()?;

    let get_result2 = String::from_utf8(output.stdout)?;
    println!("GET result (after delete): {}", get_result2);

    // Analyze results
    println!("\n=== Analysis ===");
    let delete_json: serde_json::Value = serde_json::from_str(&delete_result)?;
    let get_json: serde_json::Value = serde_json::from_str(&get_result2)?;

    println!("DELETE success: {}", delete_json["success"]);
    println!("GET after DELETE success: {}", get_json["success"]);

    if get_json["success"].as_bool().unwrap_or(true) {
        println!("❌ PROBLEM: Key still exists after DELETE!");
    } else {
        println!("✅ SUCCESS: Key was properly deleted!");
    }

    Ok(())
}
