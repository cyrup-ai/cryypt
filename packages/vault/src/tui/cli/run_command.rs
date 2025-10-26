//! Run command implementation for executing commands with vault environment variables

use super::tokenization::{SecureString, TokenizationEngine};
use super::vault_ops::ensure_unlocked;
use crate::auth::jwt_handler::JwtHandler;
use crate::core::Vault;
use crate::logging::log_security_event;
use serde_json::json;
use std::collections::HashMap;
use std::process::{Command, Stdio};
use tokio_stream::StreamExt;

pub async fn handle_run(
    vault: &Vault,
    command: Vec<String>,
    passphrase_option: Option<&str>,
    use_json: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if command.is_empty() {
        println!("Error: No command specified");
        return Ok(());
    }

    // Ensure the vault is unlocked
    if let Err(e) = ensure_unlocked(vault, passphrase_option, use_json).await {
        if use_json {
            println!(
                "{}",
                json!({
                    "success": false,
                    "operation": "run",
                    "error": format!("Failed to unlock vault: {e}")
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
                &format!("Failed to load vault variables: {e}"),
                false,
            );
            if use_json {
                println!(
                    "{}",
                    json!({
                        "success": false,
                        "operation": "run",
                        "error": format!("Failed to load vault variables: {e}")
                    })
                );
            } else {
                return Err(format!("Failed to load vault variables: {e}").into());
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
                    &format!("Failed to load vault variables: {e}"),
                    false,
                );
                if use_json {
                    println!(
                        "{}",
                        json!({
                            "success": false,
                            "operation": "run",
                            "error": format!("Failed to load vault variables: {e}")
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
            log_security_event("CLI_RUN", &format!("Failed to execute command: {e}"), false);
            if use_json {
                println!(
                    "{}",
                    json!({
                        "success": false,
                        "operation": "run",
                        "error": format!("Failed to execute command: {e}")
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
        &format!("Executed shell command via vault: {cmd_str}"),
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

/// Enhanced run command with JWT authentication and tokenization
pub async fn handle_enhanced_run(
    vault: &Vault,
    command: Vec<String>,
    namespace: Option<String>,
    jwt_token: Option<String>,
    use_json: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if command.is_empty() {
        return handle_run_error("No command specified", use_json).await;
    }

    // 1. JWT token must be provided explicitly via --jwt flag
    let token = jwt_token
        .ok_or("JWT token required for vault run operations. Use --jwt <token> flag")?;

    // 2. Validate JWT token (emergency lockdown on failure)
    let (jwt_handler, _master_key) = vault
        .get_jwt_operations()
        .await
        .map_err(|e| format!("Failed to get JWT operations: {}", e))?;

    if !jwt_handler.is_jwt_valid(&token).await {
        log_security_event(
            "CLI_RUN",
            "JWT validation failed - emergency lockdown",
            false,
        );
        return handle_run_error("Invalid or expired JWT token", use_json).await;
    }

    // 3. Load namespace keys (or all keys if no namespace specified)
    let vault_values = if let Some(ns) = &namespace {
        load_namespace_keys(vault, ns)
            .await
            .map_err(|e| format!("Failed to load namespace '{}': {}", ns, e))?
    } else {
        load_all_keys(vault)
            .await
            .map_err(|e| format!("Failed to load vault keys: {}", e))?
    };

    // 4. Parse and replace tokens
    let tokenization_engine = TokenizationEngine::new()
        .map_err(|e| format!("Failed to create tokenization engine: {}", e))?;

    // Convert SecureString values to regular strings for tokenization
    let string_values: HashMap<String, String> = vault_values
        .iter()
        .map(|(k, v)| (k.clone(), v.as_str().to_string()))
        .collect();

    let tokenized_command = tokenization_engine
        .replace_patterns(&command, &string_values)
        .map_err(|e| format!("Token replacement failed: {}", e))?;

    // 5. Execute command with async tokio::process::Command
    let output = execute_command_async(&tokenized_command)
        .await
        .map_err(|e| format!("Command execution failed: {}", e))?;

    // 6. Zeroize sensitive data
    drop(vault_values); // SecureString will zeroize on drop
    drop(string_values);

    // 7. Return output
    handle_command_output(output, use_json).await
}

/// Load keys from a specific namespace
async fn load_namespace_keys(
    vault: &Vault,
    namespace: &str,
) -> Result<HashMap<String, SecureString>, Box<dyn std::error::Error>> {
    let stream_result = vault.find_in_namespace(namespace, ".*").await?;
    let mut stream = stream_result;
    let mut values = HashMap::new();

    while let Some(result) = stream.next().await {
        match result {
            Ok((key, vault_value)) => {
                if let Ok(string_value) = vault_value.expose_as_str() {
                    values.insert(key, SecureString::new(string_value.to_string()));
                }
            }
            Err(e) => {
                return Err(format!("Failed to load key from namespace: {}", e).into());
            }
        }
    }

    Ok(values)
}

/// Load all keys from vault
async fn load_all_keys(
    vault: &Vault,
) -> Result<HashMap<String, SecureString>, Box<dyn std::error::Error>> {
    let stream_result = vault.find(".*").await?;
    let mut stream = stream_result;
    let mut values = HashMap::new();

    while let Some(result) = stream.next().await {
        match result {
            Ok((key, vault_value)) => {
                if let Ok(string_value) = vault_value.expose_as_str() {
                    values.insert(key, SecureString::new(string_value.to_string()));
                }
            }
            Err(e) => {
                return Err(format!("Failed to load vault key: {}", e).into());
            }
        }
    }

    Ok(values)
}

/// Execute command asynchronously using tokio::process::Command
async fn execute_command_async(
    command: &[String],
) -> Result<std::process::Output, Box<dyn std::error::Error>> {
    use tokio::process::Command as TokioCommand;

    if command.is_empty() {
        return Err("No command specified".into());
    }

    let mut cmd = TokioCommand::new(&command[0]);
    if command.len() > 1 {
        cmd.args(&command[1..]);
    }

    let output = cmd.output().await?;
    Ok(output)
}

/// Handle command output with appropriate formatting
async fn handle_command_output(
    output: std::process::Output,
    use_json: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    if use_json {
        println!(
            "{}",
            serde_json::json!({
                "success": output.status.success(),
                "operation": "run",
                "exit_code": output.status.code(),
                "stdout": stdout,
                "stderr": stderr
            })
        );
    } else {
        if !stdout.is_empty() {
            print!("{}", stdout);
        }
        if !stderr.is_empty() {
            eprint!("{}", stderr);
        }

        if !output.status.success() {
            if let Some(code) = output.status.code() {
                eprintln!("Command exited with non-zero status code: {}", code);
            } else {
                eprintln!("Command terminated by signal");
            }
        }
    }

    log_security_event(
        "CLI_RUN",
        &format!(
            "Executed tokenized command with exit code: {:?}",
            output.status.code()
        ),
        output.status.success(),
    );

    Ok(())
}

/// Handle errors with appropriate security responses
async fn handle_run_error(error: &str, use_json: bool) -> Result<(), Box<dyn std::error::Error>> {
    log_security_event("CLI_RUN", &format!("Run command error: {}", error), false);

    if use_json {
        println!(
            "{}",
            serde_json::json!({
                "success": false,
                "operation": "run",
                "error": error
            })
        );
    } else {
        eprintln!("Error: {}", error);
    }

    Ok(())
}
