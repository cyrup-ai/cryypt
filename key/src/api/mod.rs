//! Fluent key management API

pub mod builder_traits;
mod key_builder;
mod key_builder_entry;
mod key_entry;
mod actual_key;
mod key_generator;
mod key_retriever;
mod on_result_ext;
mod key_store_builder;
mod master_key_builder;
mod raw_key_builder;

pub use builder_traits::*;
pub use key_builder::*;
pub use key_builder_entry::KeyBuilder;
pub use actual_key::ActualKey;
pub use key_entry::Key;
pub use on_result_ext::OnResultExt;
pub use key_generator::{
    KeyGenerator, KeyGeneratorReady, KeyGeneratorWithSize, KeyGeneratorWithSizeAndStore,
    KeyGeneratorWithSizeStoreAndNamespace,
};
pub use key_retriever::{
    KeyRetriever, KeyRetrieverBatch, KeyRetrieverReady, KeyRetrieverVersionRange,
    KeyRetrieverWithStore, KeyRetrieverWithStoreAndNamespace, SecureRetrievedKey,
};
pub use master_key_builder::{
    EnvMasterKey, MasterKey, MasterKeyBuilder, MasterKeyProvider, PassphraseMasterKey, RawMasterKey,
};
pub use raw_key_builder::RawKeyBuilder;
