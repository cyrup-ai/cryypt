//! Key management API following README.md patterns

mod actual_key;
pub mod algorithm_builders;
mod key_builder;
pub mod key_generator;
pub mod key_retriever;
pub mod master_key_builder;

pub use actual_key::ActualKey;
pub use algorithm_builders::{AesKeyBuilder, RsaKeyBuilder};
pub use key_builder::{
    KeyBuilder, KeyBuilderReady, KeyBuilderWithStore, KeyBuilderWithStoreAndNamespace, KeyStore,
};

// Export KeyGenerator and KeyRetriever for vault module
pub use key_generator::KeyGenerator;
pub use key_retriever::{KeyRetriever, SecureRetrievedKey};

// Export MasterKeyBuilder for vault module
pub use master_key_builder::{MasterKeyBuilder, MasterKeyProvider, PassphraseMasterKey};
