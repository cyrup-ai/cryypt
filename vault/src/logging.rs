use log::{info, warn};
use std::time::{SystemTime, UNIX_EPOCH};

/// Logs a security-relevant event with standardized formatting
///
/// # Parameters
/// * `event_type` - Type of security event (e.g., "VAULT_UNLOCK", "PASSPHRASE_CHANGE")
/// * `details` - Additional details about the event
/// * `success` - Whether the operation was successful
pub fn log_security_event(event_type: &str, details: &str, success: bool) {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let status = if success { "SUCCESS" } else { "FAILURE" };

    if success {
        info!("[{}] {} - {}: {}", timestamp, status, event_type, details);
    } else {
        warn!("[{}] {} - {}: {}", timestamp, status, event_type, details);
    }
}
