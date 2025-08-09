//! Key management API following README.md patterns

mod actual_key;
mod key_builder;
pub mod key_generator;
pub mod key_retriever;

pub use actual_key::ActualKey;
pub use key_builder::{
    KeyBuilder, KeyBuilderReady, KeyBuilderWithStore, KeyBuilderWithStoreAndNamespace, KeyStore,
};

// Export KeyGenerator and KeyRetriever for vault module
pub use key_generator::KeyGenerator;
pub use key_retriever::{KeyRetriever, SecureRetrievedKey};
