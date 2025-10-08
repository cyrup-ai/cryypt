//! `IntoFuture` implementation for async trait support

use super::builder_states::KeyRetrieverWithHandler;
use crate::traits::KeyStorage;

// Implement IntoFuture for KeyRetrieverWithHandler to enable .await
impl<S: KeyStorage + crate::traits::KeyRetrieval, F, T> std::future::IntoFuture
    for KeyRetrieverWithHandler<S, F, T>
where
    F: FnOnce(crate::Result<Vec<u8>>) -> T + Send + 'static,
    T: cryypt_common::NotResult + Send + 'static,
    S: KeyStorage + crate::traits::KeyRetrieval + Send + 'static,
{
    type Output = T;
    type IntoFuture = std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send>>;

    fn into_future(self) -> Self::IntoFuture {
        Box::pin(self.execute("default-key-id".to_string()))
    }
}
