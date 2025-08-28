//! Cryptographically secure key retrieval module
//!
//! Contains the main retriever traits, builder patterns, and core types for secure key retrieval.

// Declare submodules
pub mod batch;
pub mod store;
pub mod version;

// New decomposed modules
pub mod builder_methods;
pub mod builder_states;
pub mod handler_execution;
pub mod into_future;
pub mod ready_state;
pub mod types;

// Re-export key types from submodules for external use
pub use batch::*;
pub use version::*;

// Re-export from decomposed modules
pub use builder_states::{
    KeyRetriever, KeyRetrieverReady, KeyRetrieverWithHandler, KeyRetrieverWithStore,
    KeyRetrieverWithStoreAndNamespace,
};
pub use types::{SecureRetrievedKey, StreamConfig};
