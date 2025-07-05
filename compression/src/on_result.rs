//! Export for on_result functionality
//! This provides the `on_result` symbol that the main cryypt crate imports

/// Identity function that can be used as a default result handler
/// This matches the README.md pattern where users can customize result handling
pub fn on_result<T>(result: T) -> T {
    result
}