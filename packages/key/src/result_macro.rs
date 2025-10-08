//! Error handling macro for fluent builders

/// Trait for builders that can produce keys with `on_result`! macro
pub trait KeyProducer {
    async fn produce_key(self) -> Result<crate::api::ActualKey, crate::KeyError>;
}
