//! Builder state types for key retrieval

use crate::traits::KeyStorage;

/// Builder for retrieving existing cryptographic keys
/// Zero-sized type for compile-time optimization
#[derive(Debug, Clone, Copy)]
pub struct KeyRetriever;

/// `KeyRetriever` with store configured
/// Generic over storage to enable monomorphization optimization
#[derive(Debug, Clone)]
pub struct KeyRetrieverWithStore<S: KeyStorage> {
    pub(crate) store: S,
}

/// `KeyRetriever` with store and namespace configured
/// Uses secure string handling for namespace
#[derive(Debug, Clone)]
pub struct KeyRetrieverWithStoreAndNamespace<S: KeyStorage> {
    pub(crate) store: S,
    pub(crate) namespace: String,
}

/// `KeyRetriever` with all parameters configured - ready to retrieve
/// Final builder state with all parameters validated
#[derive(Debug, Clone)]
pub struct KeyRetrieverReady<S: KeyStorage> {
    pub(crate) store: S,
    pub(crate) namespace: String,
    pub(crate) version: u32,
}

/// `KeyRetriever` with all parameters and result handler configured
/// Enables sexy syntax like Ok => result in closures via CRATE PRIVATE macros
#[derive(Debug)]
pub struct KeyRetrieverWithHandler<S: KeyStorage, F, T> {
    pub(crate) store: S,
    #[allow(dead_code)]
    pub(crate) namespace: String,
    #[allow(dead_code)]
    pub(crate) version: u32,
    pub(crate) result_handler: F,
    pub(crate) _phantom: std::marker::PhantomData<T>,
}
