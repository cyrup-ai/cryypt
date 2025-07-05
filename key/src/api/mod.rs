//! Key management API following README.md patterns

mod key_builder;
mod actual_key;
pub mod key_generator;
pub mod key_retriever;

pub use key_builder::{KeyBuilder, KeyBuilderWithStore, KeyBuilderWithStoreAndNamespace, KeyBuilderReady, KeyStore};
pub use actual_key::ActualKey;

// Export KeyGenerator and KeyRetriever for vault module
pub use key_generator::KeyGenerator;
pub use key_retriever::{KeyRetriever, SecureRetrievedKey};