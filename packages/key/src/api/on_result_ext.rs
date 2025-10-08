//! Extension trait for on_result! macro support

use crate::{KeyError, api::ActualKey};
use std::future::Future;
use std::pin::Pin;

/// Extension trait that enables on_result! macro for key builders
pub trait OnResultExt: Sized {
    /// The future type returned by the builder
    type Future: Future<Output = Result<ActualKey, KeyError>> + Send;
    
    /// Method called by on_result! macro for the standard pattern
    fn on_result(self) -> Self::Future;
}

/// Implement for KeyGeneratorReady
impl<S> OnResultExt for crate::api::KeyGeneratorReady<S>
where
    S: crate::traits::KeyStorage + crate::traits::KeyImport + Send + Sync + Clone + 'static,
{
    type Future = Pin<Box<dyn Future<Output = Result<ActualKey, KeyError>> + Send>>;
    
    fn on_result(self) -> Self::Future {
        Box::pin(self.generate_key())
    }
}

/// Implement for KeyRetrieverReady  
impl<S> OnResultExt for crate::api::KeyRetrieverReady<S>
where
    S: crate::traits::KeyStorage + crate::traits::KeyRetrieval + Send + Sync + Clone + 'static,
{
    type Future = Pin<Box<dyn Future<Output = Result<ActualKey, KeyError>> + Send>>;
    
    fn on_result(self) -> Self::Future {
        Box::pin(self.retrieve_key())
    }
}