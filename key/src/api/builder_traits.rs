//! Traits for the key builder pattern

/// Trait for setting the key store builder
pub trait StoreBuilderSetter {
    /// The resulting type after setting the store
    type Output;

    /// Set the key store builder
    fn with_store<B>(self, store_builder: B) -> Self::Output
    where
        B: KeyStoreBuilder + 'static;
}

/// Trait for types that can build a key store
pub trait KeyStoreBuilder: Send + Sync {
    /// The key storage backend type
    type Store: crate::key::KeyStorage;

    /// Build the key store
    fn build(self) -> Self::Store;
}

/// Trait for setting namespace
pub trait NamespaceBuilder {
    /// The resulting type after setting the namespace
    type Output;

    /// Set the namespace for the key
    fn with_namespace<T: Into<String>>(self, namespace: T) -> Self::Output;
}

/// Trait for setting version
pub trait VersionBuilder {
    /// The resulting type after setting the version
    type Output;

    /// Set the version for the key
    fn with_version(self, version: u32) -> Self::Output;
}
