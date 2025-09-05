//! Common handler functions for result and chunk processing
//!
//! These functions provide the `on_result` and `on_chunk` symbols that all crates use

/// Identity function that can be used as a default result handler
/// This matches the README.md pattern where users can customize result handling
pub fn on_result<T>(result: T) -> T {
    result
}

/// Identity function that can be used as a default chunk handler
/// This matches the README.md pattern where users can customize chunk handling
pub fn on_chunk<T>(chunk: T) -> T {
    chunk
}

/// Identity function that can be used as a default error handler
/// This matches the README.md pattern where users can customize error handling
pub fn on_error<T>(error: T) -> T {
    error
}
