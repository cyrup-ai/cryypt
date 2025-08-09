//! Run command implementation for executing commands with vault environment variables

use super::vault_ops::ensure_unlocked;
use crate::core::Vault;
use crate::logging::log_security_event;
use serde_json::json;
use std::collections::HashMap;
use std::process::{Command, Stdio};
use tokio_stream::StreamExt;

pub async fn handle_run(
    vault: &Vault,
    command: Vec<String>,
    use_json: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if command.is_empty() {
        println!("Error: No command specified");
        return Ok(());
    }

    // Ensure the vault is unlocked
    if let Err(e) = ensure_unlocked(&vault, use_json).await {
        if use_json {
            println!(
                "{}",
                json!({
                    "success": false,
                    "operation": "run",
                    "error": format!("Failed to unlock vault: {}", e)
                })
            );
            return Ok(());
        } else {
            return Err(e);
        }
    }

    // Load all vault values as environment variables
    let stream_result = vault.find(".*").await;
    let mut stream = match stream_result {
        Ok(s) => s,
        Err(e) => {
            log_security_event(
                "CLI_RUN",
                &format!("Failed to load vault variables: {}", e),
                false,
            );
            if use_json {
                println!(
                    "{}",
                    json!({
                        "success": false,
                        "operation": "run",
                        "error": format!("Failed to load vault variables: {}", e)
                    })
                );
            } else {
                return Err(format!("Failed to load vault variables: {}", e).into());
            }
            return Ok(());
        }
    };
    let mut results = Vec::new();

    while let Some(result) = stream.next().await {
        match result {
            Ok(item) => results.push(item),
            Err(e) => {
                log_security_event(
                    "CLI_RUN",
                    &format!("Failed to load vault variables: {}", e),
                    false,
                );
                if use_json {
                    println!(
                        "{}",
                        json!({
                            "success": false,
                            "operation": "run",
                            "error": format!("Failed to load vault variables: {}", e)
                        })
                    );
                    return Ok(());
                } else {
                    return Err(Box::new(e));
                }
            }
        }
    }

    let mut env_vars = HashMap::new();

    for (key, value) in results {
        if let Ok(string_value) = value.expose_as_str() {
            env_vars.insert(
                format!("VAULT_{}", key.to_uppercase()),
                string_value.to_string(),
            );
        }
    }

    // Determine which shell to use
    let shell = if cfg!(target_os = "windows") {
        "cmd"
    } else {
        "sh"
    };

    let shell_flag = if cfg!(target_os = "windows") {
        "/C"
    } else {
        "-c"
    };

    // Join the command arguments into a single string
    let cmd_str = command.join(" ");

    if !use_json {
        println!("Running command with vault variables...");
    }

    // Create and configure the command
    let mut cmd = Command::new(shell);
    cmd.arg(shell_flag)
        .arg(&cmd_str)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());

    // Collect env var keys for later use in JSON output
    let env_var_keys: Vec<String> = env_vars.keys().cloned().collect();

    // Add environment variables
    for (key, value) in env_vars {
        cmd.env(key, value);
    }

    // Execute the command
    let status = match cmd.status() {
        Ok(s) => s,
        Err(e) => {
            log_security_event(
                "CLI_RUN",
                &format!("Failed to execute command: {}", e),
                false,
            );
            if use_json {
                println!(
                    "{}",
                    json!({
                        "success": false,
                        "operation": "run",
                        "error": format!("Failed to execute command: {}", e)
                    })
                );
                return Ok(());
            } else {
                return Err(Box::new(e));
            }
        }
    };

    log_security_event(
        "CLI_RUN",
        &format!("Executed shell command via vault: {}", cmd_str),
        true,
    );

    if use_json {
        println!(
            "{}",
            json!({
                "success": status.success(),
                "operation": "run",
                "command": cmd_str,
                "exit_code": status.code(),
                "env_vars": env_var_keys
            })
        );
    } else if !status.success() {
        if let Some(code) = status.code() {
            println!("Command exited with non-zero status code: {}", code);
        } else {
            println!("Command terminated by signal");
        }
    }

    Ok(())
}
