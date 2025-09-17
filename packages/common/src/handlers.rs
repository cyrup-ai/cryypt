//! Common handler functions for result and chunk processing
//!
//! These functions provide the `on_result` and `on_chunk` symbols that all crates use

/// Default result handler that logs successful operations and passes through results
/// This matches the README.md pattern where users can customize result handling
pub fn on_result<T>(result: T) -> T {
    // Log successful operation for debugging
    tracing::debug!("Operation completed successfully");
    result
}

/// Default chunk handler that validates and processes data chunks
/// This matches the README.md pattern where users can customize chunk handling
pub fn on_chunk<T>(chunk: T) -> T {
    // Log chunk processing for debugging
    tracing::trace!("Processing data chunk");
    chunk
}

/// Default error handler that logs errors before passing them through
/// This matches the README.md pattern where users can customize error handling
pub fn on_error<T: std::fmt::Debug>(error: T) -> T {
    // Log error for debugging and monitoring
    tracing::warn!("Error occurred: {error:?}");
    error
}
