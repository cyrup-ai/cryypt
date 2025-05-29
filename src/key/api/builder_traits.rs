//! Traits for the key builder pattern

/// Trait for setting the key store builder
pub trait StoreBuilderSetter {
    type Output;
    
    /// Set the key store builder
    fn with_store<B>(self, store_builder: B) -> Self::Output
    where
        B: KeyStoreBuilder + 'static;
}

/// Trait for types that can build a key store
pub trait KeyStoreBuilder: Send + Sync {
    type Store: crate::key::KeyStorage;
    
    /// Build the key store
    fn build(self) -> Self::Store;
}

/// Trait for setting namespace
pub trait NamespaceBuilder {
    type Output;
    
    /// Set the namespace for the key
    fn with_namespace<T: Into<String>>(self, namespace: T) -> Self::Output;
}

/// Trait for setting version
pub trait VersionBuilder {
    type Output;
    
    /// Set the version for the key
    fn with_version(self, version: u32) -> Self::Output;
}