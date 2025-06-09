use dialoguer::{Password, theme::ColorfulTheme};
use crate::tui::Commands;
use crate::vault::Vault;
use crate::logging::log_security_event;
use std::process::{Command, Stdio};
use std::collections::HashMap;
use serde_json::json;

/// Process the CLI command
/// Ensures the vault is unlocked by prompting for a passphrase if needed
/// If using JSON mode or CYSEC_PASSPHRASE environment variable, no prompt is shown
async fn ensure_unlocked(vault: &Vault, use_json: bool) -> Result<(), Box<dyn std::error::Error>> {
    if vault.is_locked().await {
        // First check for env var passphrase - allows non-interactive use
        let passphrase = if let Ok(pass) = std::env::var("CYSEC_PASSPHRASE") {
            log_security_event("CLI_UNLOCK", "Using passphrase from environment variable", true);
            pass
        } else if use_json {
            // In JSON mode, don't prompt interactively - return an error instead
            log_security_event("CLI_UNLOCK", "Failed to unlock vault in JSON mode - no passphrase available", false);
            return Err("No passphrase provided. Set CYSEC_PASSPHRASE environment variable when using --json".into());
        } else {
            // Only prompt interactively in normal mode
            Password::with_theme(&ColorfulTheme::default())
                .with_prompt("Enter vault passphrase")
                .interact()?
        };
        
        match vault.unlock(&passphrase).await {
            Ok(_) => {
                log_security_event("CLI_UNLOCK", "Vault unlocked for CLI operation", true);
            }
            Err(e) => {
                log_security_event("CLI_UNLOCK", &format!("Failed to unlock vault: {}", e), false);
                return Err(Box::new(e));
            }
        }
    }
    Ok(())
}

pub async fn process_command(vault: &Vault, command: Commands, use_json: bool) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        Commands::Save {} => {
            if let Err(e) = ensure_unlocked(&vault, use_json).await {
                if use_json {
                    println!("{}", json!({
                        "success": false,
                        "operation": "save",
                        "error": format!("Failed to unlock vault: {}", e)
                    }));
                    return Ok(());
                } else {
                    return Err(e);
                }
            }
            
            if !use_json {
                println!("Saving vault data to disk...");
            }
            
            // For the "Save" command, we need to lock and unlock to save to disk
            match vault.lock().await {
                Ok(_) => {
                    // Re-unlock with same passphrase that was used earlier
                    let passphrase = match std::env::var("CYSEC_PASSPHRASE") {
                        Ok(pass) => pass,
                        Err(_) => {
                            if use_json {
                                println!("{}", json!({
                                    "success": false,
                                    "operation": "save",
                                    "error": "No passphrase available for re-unlocking vault"
                                }));
                                return Ok(());
                            } else {
                                Password::with_theme(&ColorfulTheme::default())
                                    .with_prompt("Enter vault passphrase to re-unlock")
                                    .interact()?
                            }
                        }
                    };
                    
                    match vault.unlock(&passphrase).await {
                        Ok(_) => {
                            log_security_event("CLI_SAVE", "Vault data saved", true);
                            
                            if use_json {
                                println!("{}", json!({
                                    "success": true,
                                    "operation": "save"
                                }));
                            } else {
                                println!("Vault data saved successfully");
                            }
                        }
                        Err(e) => {
                            log_security_event("CLI_SAVE", &format!("Failed to re-unlock vault after save: {}", e), false);
                            
                            if use_json {
                                println!("{}", json!({
                                    "success": false,
                                    "operation": "save",
                                    "error": format!("Failed to re-unlock vault after save: {}", e)
                                }));
                                return Ok(());
                            } else {
                                return Err(Box::new(e));
                            }
                        }
                    }
                },
                Err(e) => {
                    log_security_event("CLI_SAVE", &format!("Failed to save vault data: {}", e), false);
                    
                    if use_json {
                        println!("{}", json!({
                            "success": false,
                            "operation": "save",
                            "error": format!("Failed to save vault data: {}", e)
                        }));
                        return Ok(());
                    } else {
                        return Err(Box::new(e));
                    }
                }
            }
        },
        Commands::Run { command } => {
            if command.is_empty() {
                println!("Error: No command specified");
                return Ok(());
            }
            
            // Ensure the vault is unlocked
            if let Err(e) = ensure_unlocked(&vault, use_json).await {
                if use_json {
                    println!("{}", json!({
                        "success": false,
                        "operation": "run",
                        "error": format!("Failed to unlock vault: {}", e)
                    }));
                    return Ok(());
                } else {
                    return Err(e);
                }
            }
            
            // Load all vault values as environment variables
            let results = match vault.find(".*").await {
                Ok(r) => r,
                Err(e) => {
                    log_security_event("CLI_RUN", &format!("Failed to load vault variables: {}", e), false);
                    if use_json {
                        println!("{}", json!({
                            "success": false,
                            "operation": "run",
                            "error": format!("Failed to load vault variables: {}", e)
                        }));
                        return Ok(());
                    } else {
                        return Err(Box::new(e));
                    }
                }
            };
            
            let mut env_vars = HashMap::new();
            
            for (key, value) in results {
                if let Some(string_value) = value.as_str() {
                    env_vars.insert(format!("VAULT_{}", key.to_uppercase()), string_value.to_string());
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
                    log_security_event("CLI_RUN", &format!("Failed to execute command: {}", e), false);
                    if use_json {
                        println!("{}", json!({
                            "success": false,
                            "operation": "run",
                            "error": format!("Failed to execute command: {}", e)
                        }));
                        return Ok(());
                    } else {
                        return Err(Box::new(e));
                    }
                }
            };
            
            log_security_event("CLI_RUN", &format!("Executed shell command via vault: {}", cmd_str), true);
            
            if use_json {
                println!("{}", json!({
                    "success": status.success(),
                    "operation": "run",
                    "command": cmd_str,
                    "exit_code": status.code(),
                    "env_vars": env_var_keys
                }));
            } else if !status.success() {
                if let Some(code) = status.code() {
                    println!("Command exited with non-zero status code: {}", code);
                } else {
                    println!("Command terminated by signal");
                }
            }
        },
        
        Commands::Put { key, value } => {
            if let Err(e) = ensure_unlocked(&vault, use_json).await {
                if use_json {
                    println!("{}", json!({
                        "success": false,
                        "operation": "put",
                        "error": format!("Failed to unlock vault: {}", e)
                    }));
                    return Ok(());
                } else {
                    return Err(e);
                }
            }
            
            if !use_json {
                println!("Storing value for key '{}'...", key);
            }
            
            match vault.put(&key, &value).await {
                Ok(_) => {
                    log_security_event("CLI_PUT", &format!("Stored value for key: {}", key), true);
                    
                    if use_json {
                        println!("{}", json!({
                            "success": true,
                            "operation": "put",
                            "key": key
                        }));
                    } else {
                        println!("Value stored successfully");
                    }
                },
                Err(e) => {
                    log_security_event("CLI_PUT", &format!("Failed to store value for key {}: {}", key, e), false);
                    
                    if use_json {
                        println!("{}", json!({
                            "success": false,
                            "operation": "put",
                            "error": format!("Failed to store value: {}", e)
                        }));
                        return Ok(());
                    } else {
                        return Err(Box::new(e));
                    }
                }
            }
        },
        
        Commands::Get { key } => {
            if let Err(e) = ensure_unlocked(&vault, use_json).await {
                if use_json {
                    println!("{}", json!({
                        "success": false,
                        "operation": "get",
                        "error": format!("Failed to unlock vault: {}", e)
                    }));
                    return Ok(());
                } else {
                    return Err(e);
                }
            }
            
            if !use_json {
                println!("Retrieving value for key '{}'...", key);
            }
            
            match vault.get(&key).await {
                Ok(value) => {
                    let value_str = value.as_str().unwrap_or("[non-string value]");
                    log_security_event("CLI_GET", &format!("Retrieved value for key: {}", key), true);
                    
                    if use_json {
                        println!("{}", json!({
                            "success": true,
                            "operation": "get",
                            "key": key,
                            "value": value_str
                        }));
                    } else {
                        println!("Value: {}", value_str);
                    }
                },
                Err(e) => {
                    log_security_event("CLI_GET", &format!("Failed to retrieve value for key {}: {}", key, e), false);
                    
                    if use_json {
                        println!("{}", json!({
                            "success": false,
                            "operation": "get",
                            "key": key,
                            "error": format!("Failed to retrieve value: {}", e)
                        }));
                        return Ok(());
                    } else {
                        return Err(Box::new(e));
                    }
                }
            }
        },
        
        Commands::Delete { key } => {
            if let Err(e) = ensure_unlocked(&vault, use_json).await {
                if use_json {
                    println!("{}", json!({
                        "success": false,
                        "operation": "delete",
                        "error": format!("Failed to unlock vault: {}", e)
                    }));
                    return Ok(());
                } else {
                    return Err(e);
                }
            }
            
            if !use_json {
                println!("Deleting key '{}'...", key);
            }
            
            match vault.delete(&key).await {
                Ok(_) => {
                    log_security_event("CLI_DELETE", &format!("Deleted key: {}", key), true);
                    
                    if use_json {
                        println!("{}", json!({
                            "success": true,
                            "operation": "delete",
                            "key": key
                        }));
                    } else {
                        println!("Key deleted successfully");
                    }
                },
                Err(e) => {
                    log_security_event("CLI_DELETE", &format!("Failed to delete key {}: {}", key, e), false);
                    
                    if use_json {
                        println!("{}", json!({
                            "success": false,
                            "operation": "delete",
                            "key": key,
                            "error": format!("Failed to delete key: {}", e)
                        }));
                        return Ok(());
                    } else {
                        return Err(Box::new(e));
                    }
                }
            }
        },
        
        Commands::List {} => {
            if let Err(e) = ensure_unlocked(&vault, use_json).await {
                if use_json {
                    println!("{}", json!({
                        "success": false,
                        "operation": "list",
                        "error": format!("Failed to unlock vault: {}", e)
                    }));
                    return Ok(());
                } else {
                    return Err(e);
                }
            }
            
            if !use_json {
                println!("Listing all keys...");
            }
            
            match vault.find(".*").await {
                Ok(results) => {
                    log_security_event("CLI_LIST", "Listed all keys", true);
                    
                    if use_json {
                        let keys: Vec<String> = results.iter().map(|(k, _)| k.clone()).collect();
                        println!("{}", json!({
                            "success": true,
                            "operation": "list",
                            "keys": keys,
                            "count": keys.len()
                        }));
                    } else {
                        if results.is_empty() {
                            println!("No keys found in vault");
                        } else {
                            println!("Keys in vault:");
                            for (key, _) in results {
                                println!("- {}", key);
                            }
                        }
                    }
                },
                Err(e) => {
                    log_security_event("CLI_LIST", &format!("Failed to list keys: {}", e), false);
                    
                    if use_json {
                        println!("{}", json!({
                            "success": false,
                            "operation": "list",
                            "error": format!("Failed to list keys: {}", e)
                        }));
                        return Ok(());
                    } else {
                        return Err(Box::new(e));
                    }
                }
            }
        },
        
        Commands::Find { pattern } => {
            if let Err(e) = ensure_unlocked(&vault, use_json).await {
                if use_json {
                    println!("{}", json!({
                        "success": false,
                        "operation": "find",
                        "error": format!("Failed to unlock vault: {}", e)
                    }));
                    return Ok(());
                } else {
                    return Err(e);
                }
            }
            
            if !use_json {
                println!("Finding keys matching pattern '{}'...", pattern);
            }
            
            match vault.find(&pattern).await {
                Ok(results) => {
                    log_security_event("CLI_FIND", &format!("Found keys matching pattern: {}", pattern), true);
                    
                    if use_json {
                        let entries: Vec<serde_json::Value> = results.iter()
                            .map(|(k, v)| {
                                json!({
                                    "key": k,
                                    "value": v.as_str().unwrap_or("[non-string value]")
                                })
                            })
                            .collect();
                            
                        println!("{}", json!({
                            "success": true,
                            "operation": "find",
                            "pattern": pattern,
                            "entries": entries,
                            "count": entries.len()
                        }));
                    } else {
                        if results.is_empty() {
                            println!("No keys found matching pattern");
                        } else {
                            println!("Keys matching pattern:");
                            for (key, value) in results {
                                println!("- {}: {}", key, value.as_str().unwrap_or("[non-string value]"));
                            }
                        }
                    }
                },
                Err(e) => {
                    log_security_event("CLI_FIND", &format!("Failed to find keys matching pattern {}: {}", pattern, e), false);
                    
                    if use_json {
                        println!("{}", json!({
                            "success": false,
                            "operation": "find",
                            "pattern": pattern,
                            "error": format!("Failed to find keys: {}", e)
                        }));
                        return Ok(());
                    } else {
                        return Err(Box::new(e));
                    }
                }
            }
        },
        
        Commands::ChangePassphrase { old_passphrase, new_passphrase } => {
            let old_pass = match old_passphrase {
                Some(pass) => pass,
                None => Password::with_theme(&ColorfulTheme::default())
                    .with_prompt("Enter current passphrase")
                    .interact()?
            };
            
            let new_pass = match new_passphrase {
                Some(pass) => pass,
                None => Password::with_theme(&ColorfulTheme::default())
                    .with_prompt("Enter new passphrase")
                    .with_confirmation("Confirm new passphrase", "Passphrases don't match")
                    .interact()?
            };
            
            if !use_json {
                println!("Changing passphrase...");
            }
            
            // First unlock with old passphrase if locked
            if vault.is_locked().await {
                log_security_event("CLI_UNLOCK", "Attempting to unlock vault for passphrase change", true);
                match vault.unlock(&old_pass).await {
                    Ok(_) => {
                        log_security_event("CLI_UNLOCK", "Vault unlocked for passphrase change", true);
                    }
                    Err(e) => {
                        log_security_event("CLI_UNLOCK", &format!("Failed to unlock vault for passphrase change: {}", e), false);
                        
                        if use_json {
                            println!("{}", json!({
                                "success": false,
                                "operation": "change_passphrase",
                                "error": format!("Failed to unlock vault: {}", e)
                            }));
                            return Ok(());
                        } else {
                            return Err(Box::new(e));
                        }
                    }
                }
            }
            
            // Use the change_passphrase method directly
            match vault.change_passphrase(&old_pass, &new_pass).await {
                Ok(_) => {
                    log_security_event("CLI_PASSPHRASE_CHANGE", "Passphrase changed successfully", true);
                    
                    if use_json {
                        println!("{}", json!({
                            "success": true,
                            "operation": "change_passphrase"
                        }));
                    } else {
                        println!("Passphrase changed successfully");
                    }
                }
                Err(e) => {
                    log_security_event("CLI_PASSPHRASE_CHANGE", &format!("Failed to change passphrase: {}", e), false);
                    
                    if use_json {
                        println!("{}", json!({
                            "success": false,
                            "operation": "change_passphrase",
                            "error": format!("Failed to change passphrase: {}", e)
                        }));
                        return Ok(());
                    } else {
                        return Err(Box::new(e));
                    }
                }
            }
        }
    }
    
    Ok(())
}
