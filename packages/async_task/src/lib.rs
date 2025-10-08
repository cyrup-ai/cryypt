//! # Async Task Coordination Library
//!
//! This crate provides async patterns without using `async_trait` or blocking operations.
//! It focuses on channel-based coordination and proper async/await patterns.

pub mod channel;
pub mod executor;
pub mod patterns;
pub mod task;

pub use channel::{AsyncChannel, ChannelError};
pub use executor::{AsyncExecutor, ExecutorConfig};
pub use patterns::{AsyncPattern, PatternBuilder};
pub use task::{AsyncTask, TaskError, TaskResult};

/// Re-export common types
pub type Result<T> = std::result::Result<T, TaskError>;
