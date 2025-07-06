//! Vault operations for CLI commands

use super::commands::Commands;
use crate::core::Vault;
use crate::logging::log_security_event;
use dialoguer::{Password, theme::ColorfulTheme};
use serde_json::json;
use tokio_stream::StreamExt;

/// Ensures the vault is unlocked by prompting for a passphrase if needed
/// If using JSON mode or CYSEC_PASSPHRASE environment variable, no prompt is shown
pub async fn ensure_unlocked(vault: &Vault, use_json: bool) -> Result<(), Box<dyn std::error::Error>> {
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

pub async fn handle_save(vault: &Vault, use_json: bool) -> Result<(), Box<dyn std::error::Error>> {
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
    Ok(())
}

pub async fn handle_put(vault: &Vault, key: &str, value: &str, use_json: bool) -> Result<(), Box<dyn std::error::Error>> {
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
    
    match vault.put(key, value).await {
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
    Ok(())
}

pub async fn handle_get(vault: &Vault, key: &str, use_json: bool) -> Result<(), Box<dyn std::error::Error>> {
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
    
    match vault.get(key).await {
        Ok(request) => {
            match request.await {
                Ok(value) => {
                    log_security_event("CLI_GET", &format!("Retrieved value for key: {}", key), true);
                    
                    match value {
                        Some(v) => {
                            let value_str = v.expose_as_str().unwrap_or("[non-string value]");
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
                        None => {
                            if use_json {
                                println!("{}", json!({
                                    "success": true,
                                    "operation": "get",
                                    "key": key,
                                    "value": "[not found]"
                                }));
                            } else {
                                println!("Value: [not found]");
                            }
                        }
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
                        return Err(format!("Failed to retrieve value: {}", e).into());
                    }
                }
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
    Ok(())
}

pub async fn handle_delete(vault: &Vault, key: &str, use_json: bool) -> Result<(), Box<dyn std::error::Error>> {
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
    
    match vault.delete(key).await {
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
    Ok(())
}

pub async fn handle_list(vault: &Vault, use_json: bool) -> Result<(), Box<dyn std::error::Error>> {
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
    
    let stream_result = vault.find(".*").await;
    let mut stream = match stream_result {
        Ok(s) => s,
        Err(e) => {
            log_security_event("CLI_LIST", &format!("Failed to list keys: {}", e), false);
            if use_json {
                println!("{}", json!({
                    "success": false,
                    "operation": "list",
                    "error": format!("Failed to list keys: {}", e)
                }));
            } else {
                return Err(format!("Failed to list keys: {}", e).into());
            }
            return Ok(());
        }
    };
    let mut results = Vec::new();
    
    while let Some(result) = stream.next().await {
        match result {
            Ok(item) => results.push(item),
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
    }
    
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
    Ok(())
}

pub async fn handle_find(vault: &Vault, pattern: &str, use_json: bool) -> Result<(), Box<dyn std::error::Error>> {
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
    
    let stream_result = vault.find(pattern).await;
    let mut stream = match stream_result {
        Ok(s) => s,
        Err(e) => {
            log_security_event("CLI_FIND", &format!("Failed to find keys matching pattern {}: {}", pattern, e), false);
            if use_json {
                println!("{}", json!({
                    "success": false,
                    "operation": "find",
                    "pattern": pattern,
                    "error": format!("Failed to find keys: {}", e)
                }));
            } else {
                return Err(format!("Failed to find keys: {}", e).into());
            }
            return Ok(());
        }
    };
    let mut results = Vec::new();
    
    while let Some(result) = stream.next().await {
        match result {
            Ok(item) => results.push(item),
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
    }
    
    log_security_event("CLI_FIND", &format!("Found keys matching pattern: {}", pattern), true);
    
    if use_json {
        let entries: Vec<serde_json::Value> = results.iter()
                    .map(|(k, v)| {
                        json!({
                            "key": k,
                            "value": v.expose_as_str().unwrap_or("[non-string value]")
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
                println!("- {}: {}", key, value.expose_as_str().unwrap_or("[non-string value]"));
            }
        }
    }
    Ok(())
}

pub async fn handle_change_passphrase(
    vault: &Vault,
    old_passphrase: Option<String>,
    new_passphrase: Option<String>,
    use_json: bool
) -> Result<(), Box<dyn std::error::Error>> {
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
    Ok(())
}