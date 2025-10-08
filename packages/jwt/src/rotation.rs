//! JWT key rotation following README.md patterns

// Re-export rotator types for compatibility
pub use crate::api::rotator_builder::JwtRotator;

/// Create a default JWT rotator
pub fn create_default_rotator() -> JwtRotator {
    JwtRotator::new()
}

/// Validate a JWT rotator configuration
pub fn validate_rotator(rotator: &JwtRotator) -> bool {
    // Check if rotator has at least one key configured
    let key_count = rotator.list_keys().len();
    let has_current_key = rotator.get_current_key().is_some();

    key_count > 0 && has_current_key
}
