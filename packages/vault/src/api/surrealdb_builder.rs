//! SurrealDB vault builder following polymorphic pattern

use crate::{LocalVaultProvider, VaultConfig, VaultError, VaultResult, VaultValue};
use futures::Stream;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;

/// Type-state marker for no connection configured
pub struct NoConnection;

/// Type-state marker for connection configured
pub struct HasConnection(pub String);

/// Builder for SurrealDB vault operations
pub struct SurrealDbBuilder<C> {
    pub(crate) connection: C,
}

/// Builder with result handler
pub struct SurrealDbBuilderWithHandler<C, F, T> {
    pub(crate) connection: C,
    pub(crate) result_handler: F,
    pub(crate) _phantom: std::marker::PhantomData<T>,
}

/// Builder with chunk handler for streaming pattern
pub struct SurrealDbBuilderWithChunk<C, F> {
    pub(crate) connection: C,
    pub(crate) chunk_handler: F,
}

impl SurrealDbBuilder<NoConnection> {
    /// Create a new SurrealDB builder
    pub fn new() -> Self {
        Self {
            connection: NoConnection,
        }
    }

    /// Set connection string - README.md pattern
    pub fn with_connection(self, connection: String) -> SurrealDbBuilder<HasConnection> {
        SurrealDbBuilder {
            connection: HasConnection(connection),
        }
    }
}

impl Default for SurrealDbBuilder<NoConnection> {
    fn default() -> Self {
        Self::new()
    }
}

impl<C> SurrealDbBuilder<C> {
    /// Add on_result handler - transforms pattern matching internally
    pub fn on_result<F>(self, handler: F) -> SurrealDbBuilderWithHandler<C, F, Vec<u8>>
    where
        F: Fn(VaultResult<Vec<u8>>) -> Vec<u8> + Send + 'static,
    {
        SurrealDbBuilderWithHandler {
            connection: self.connection,
            result_handler: handler,
            _phantom: std::marker::PhantomData,
        }
    }

    /// Add on_chunk handler - transforms pattern matching internally
    pub fn on_chunk<F>(self, handler: F) -> SurrealDbBuilderWithChunk<C, F>
    where
        F: Fn(VaultResult<Vec<u8>>) -> Vec<u8> + Send + 'static,
    {
        SurrealDbBuilderWithChunk {
            connection: self.connection,
            chunk_handler: handler,
        }
    }
}

// Single result operations
impl<F, T> SurrealDbBuilderWithHandler<HasConnection, F, T>
where
    F: FnOnce(VaultResult<Vec<u8>>) -> T + Send + 'static,
    T: cryypt_common::NotResult + Send + 'static,
{
    /// Store data in vault
    pub async fn store<K, V>(self, key: K, value: V) -> T
    where
        K: Into<String>,
        V: Into<Vec<u8>>,
    {
        let key = key.into();
        let value = value.into();

        let result = surrealdb_store_impl(self.connection.0, key, value).await;

        (self.result_handler)(result)
    }

    /// Retrieve data from vault
    pub async fn retrieve<K>(self, key: K) -> T
    where
        K: Into<String>,
    {
        let key = key.into();

        let result = surrealdb_retrieve_impl(self.connection.0, key).await;

        (self.result_handler)(result)
    }
}

// Streaming operations
impl<F> SurrealDbBuilderWithChunk<HasConnection, F>
where
    F: Fn(VaultResult<Vec<u8>>) -> Vec<u8> + Send + 'static,
{
    /// Store multiple values with streaming
    pub fn store_batch<I, K, V>(self, items: I) -> impl Stream<Item = Vec<u8>>
    where
        I: IntoIterator<Item = (K, V)> + Send + 'static,
        K: Into<String> + Send + 'static,
        V: Into<Vec<u8>> + Send + 'static,
    {
        let (tx, rx) = mpsc::channel(32);
        let connection = self.connection.0;
        let handler = self.chunk_handler;

        tokio::task::spawn_local(async move {
            let items: Vec<_> = items.into_iter().collect();
            for (key, value) in items {
                // Yield control to allow other tasks to run
                tokio::task::yield_now().await;

                let key = key.into();
                let value = value.into();

                // Store individual item
                let result = surrealdb_store_impl(connection.clone(), key, value).await;

                // Apply handler and send result
                let processed_chunk = handler(result);

                if tx.send(processed_chunk).await.is_err() {
                    break; // Receiver dropped
                }
            }
        });

        ReceiverStream::new(rx)
    }

    /// Retrieve multiple values with streaming
    pub fn retrieve_batch<I, K>(self, keys: I) -> impl Stream<Item = Vec<u8>>
    where
        I: IntoIterator<Item = K> + Send + 'static,
        K: Into<String> + Send + 'static,
    {
        let (tx, rx) = mpsc::channel(32);
        let connection = self.connection.0;
        let handler = self.chunk_handler;

        tokio::task::spawn_local(async move {
            let keys: Vec<_> = keys.into_iter().collect();
            for key in keys {
                // Yield control to allow other tasks to run
                tokio::task::yield_now().await;

                let key = key.into();

                // Retrieve individual item
                let result = surrealdb_retrieve_impl(connection.clone(), key).await;

                // Apply handler and send result
                let processed_chunk = handler(result);

                if tx.send(processed_chunk).await.is_err() {
                    break; // Receiver dropped
                }
            }
        });

        ReceiverStream::new(rx)
    }
}

// Production SurrealDB operations using real LocalVaultProvider
async fn surrealdb_store_impl(
    connection_path: String,
    key: String,
    value: Vec<u8>,
) -> VaultResult<Vec<u8>> {
    // Create VaultConfig with custom vault path
    let config = VaultConfig {
        vault_path: connection_path.into(),
        ..Default::default()
    };

    // Create LocalVaultProvider instance
    let provider = LocalVaultProvider::new(config).await?;

    // Convert bytes to VaultValue
    let vault_value = VaultValue::from_bytes(value);

    // Use real LocalVaultProvider put operation
    provider.put(&key, &vault_value).await?;

    // Return success indicator (matching original API)
    Ok(b"stored".to_vec())
}

async fn surrealdb_retrieve_impl(connection_path: String, key: String) -> VaultResult<Vec<u8>> {
    // Create VaultConfig with custom vault path
    let config = VaultConfig {
        vault_path: connection_path.into(),
        ..Default::default()
    };

    // Create LocalVaultProvider instance
    let provider = LocalVaultProvider::new(config).await?;

    // Use real LocalVaultProvider get operation
    match provider.get(&key).await? {
        Some(vault_value) => Ok(vault_value.expose_secret().to_vec()),
        None => Err(VaultError::ItemNotFound),
    }
}
