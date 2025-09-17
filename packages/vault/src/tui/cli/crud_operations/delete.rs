//! Delete operations for vault CLI commands

use super::super::unlock_operations::ensure_unlocked;
use crate::core::Vault;
use crate::logging::log_security_event;
use serde_json::json;

pub async fn handle_delete(
    vault: &Vault,
    key: &str,
    namespace: Option<&str>,
    passphrase_option: Option<&str>,
    use_json: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Err(e) = ensure_unlocked(vault, passphrase_option, use_json).await {
        if use_json {
            println!(
                "{}",
                json!({
                    "success": false,
                    "operation": "delete",
                    "error": format!("Failed to unlock vault: {e}")
                })
            );
            return Ok(());
        } else {
            return Err(e);
        }
    }

    if !use_json {
        if let Some(ns) = namespace {
            println!("Deleting key '{}' from namespace '{}'...", key, ns);
        } else {
            println!("Deleting key '{}'...", key);
        }
    }

    // Use namespace-aware delete operation if namespace is provided
    let delete_result = if let Some(ns) = namespace {
        vault.delete_from_namespace(ns, key).await
    } else {
        vault.delete(key).await
    };

    match delete_result {
        Ok(_) => {
            let log_msg = if let Some(ns) = namespace {
                format!("Deleted key: {key} from namespace: {ns}")
            } else {
                format!("Deleted key: {key}")
            };
            log_security_event("CLI_DELETE", &log_msg, true);

            if use_json {
                let mut response = json!({
                    "success": true,
                    "operation": "delete",
                    "key": key
                });
                if let Some(ns) = namespace {
                    response["namespace"] = json!(ns);
                }
                println!("{}", response);
            } else {
                println!("Key deleted successfully");
            }
        }
        Err(e) => {
            let log_msg = if let Some(ns) = namespace {
                format!("Failed to delete key {key} from namespace {ns}: {e}")
            } else {
                format!("Failed to delete key {key}: {e}")
            };
            log_security_event("CLI_DELETE", &log_msg, false);

            if use_json {
                let mut response = json!({
                    "success": false,
                    "operation": "delete",
                    "key": key,
                    "error": format!("Failed to delete key: {e}")
                });
                if let Some(ns) = namespace {
                    response["namespace"] = json!(ns);
                }
                println!("{}", response);
                return Ok(());
            } else {
                return Err(Box::new(e));
            }
        }
    }
    Ok(())
}
