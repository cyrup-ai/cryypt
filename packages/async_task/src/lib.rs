//! # Async Task Coordination Library
//! 
//! This crate provides async patterns without using `async_trait` or blocking operations.
//! It focuses on channel-based coordination and proper async/await patterns.

pub mod task;
pub mod channel;
pub mod executor;
pub mod patterns;

pub use task::{AsyncTask, TaskResult, TaskError};
pub use channel::{AsyncChannel, ChannelError};
pub use executor::{AsyncExecutor, ExecutorConfig};
pub use patterns::{AsyncPattern, PatternBuilder};

/// Re-export common types
pub type Result<T> = std::result::Result<T, TaskError>;

