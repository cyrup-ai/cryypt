use crate::core::VaultValue;
use crate::error::{VaultError, VaultResult};
use futures_core::Stream;
use pin_project::pin_project;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
// Remove Duration import if not used elsewhere
// use std::time::Duration;
use secrecy::SecretString;
use tokio::sync::{mpsc, oneshot}; // Use secrecy::SecretString for Passphrase

// --- Type Aliases ---

/// Type alias for a passphrase, ensuring it's zeroized in memory.
pub type Passphrase = SecretString; // Use SecretString from secrecy crate

// --- Request Types (Implementing Future/Stream) ---

// Generic request type for operations returning a single value or unit
#[pin_project]
#[derive(Debug)]
pub struct VaultRequest<T> {
    #[pin]
    receiver: oneshot::Receiver<VaultResult<T>>,
}

impl<T> VaultRequest<T> {
    // This constructor would typically be called by the trait implementation
    pub(crate) fn new(receiver: oneshot::Receiver<VaultResult<T>>) -> Self {
        Self { receiver }
    }
}

impl<T> Future for VaultRequest<T> {
    type Output = VaultResult<T>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.project().receiver.poll(cx) {
            Poll::Ready(Ok(result)) => Poll::Ready(result),
            Poll::Ready(Err(_)) => Poll::Ready(Err(VaultError::Other(
                "Vault operation channel closed unexpectedly".to_string(),
            ))),
            Poll::Pending => Poll::Pending,
        }
    }
}

// Specific Type Aliases for Readability
pub type VaultGetRequest = VaultRequest<Option<VaultValue>>;
pub type VaultUnitRequest = VaultRequest<()>; // For set, delete, lock, unlock etc.
pub type VaultBoolRequest = VaultRequest<bool>; // For put_if_absent
pub type VaultSaveRequest = VaultRequest<()>;
pub type VaultChangePassphraseRequest = VaultRequest<()>;
pub type VaultPutAllRequest = VaultRequest<()>;
pub type VaultListNamespacesRequest = VaultRequest<Vec<String>>;

// Generic request type for operations returning a stream of values
#[pin_project]
#[derive(Debug)]
pub struct VaultStreamRequest<T> {
    #[pin]
    receiver: mpsc::Receiver<VaultResult<T>>,
}

impl<T> VaultStreamRequest<T> {
    // This constructor would typically be called by the trait implementation
    pub(crate) fn new(receiver: mpsc::Receiver<VaultResult<T>>) -> Self {
        Self { receiver }
    }
}

impl<T> Stream for VaultStreamRequest<T> {
    type Item = VaultResult<T>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.project().receiver.poll_recv(cx)
    }
}

// Specific Type Aliases for Stream Readability
pub type VaultListRequest = VaultStreamRequest<String>;
pub type VaultFindRequest = VaultStreamRequest<(String, VaultValue)>;

/// Defines the core vault operations using awaitable return types
pub trait VaultOperation: Send + Sync + std::any::Any + 'static {
    /// Get the operation name
    fn name(&self) -> &str;

    /// Check if user is authenticated (JWT-based)
    fn is_authenticated(&self) -> bool;

    /// Check if vault file is PQCrypto armored
    fn is_locked(&self) -> bool; // Remains synchronous

    /// Check if master key is available for encryption
    fn has_master_key(&self) -> bool;

    /// Unlock the vault with a passphrase. Returns a request that resolves when unlocked.
    fn unlock(&self, passphrase: &Passphrase) -> VaultUnitRequest;

    /// Lock the vault. Returns a request that resolves when locked.
    fn lock(&self) -> VaultUnitRequest;

    /// Check if this provider supports time-to-live for secrets
    fn supports_ttl(&self) -> bool {
        false
    }

    /// Check if this provider supports versioning of secrets
    fn supports_versioning(&self) -> bool {
        false
    }

    /// Check if this provider supports tagging secrets
    fn supports_tags(&self) -> bool {
        false
    }

    /// Check if this provider supports namespaces
    fn supports_namespaces(&self) -> bool {
        false
    }

    /// Check if this provider supports encryption
    fn supports_encryption(&self) -> bool {
        false
    }

    /// Get the encryption type used by this provider
    fn encryption_type(&self) -> &str {
        "none"
    }

    /// Check if this provider supports defense-in-depth encryption (cascading layers)
    fn supports_defense_in_depth(&self) -> bool {
        false
    }

    /// Store a value with the given key. Returns a request that resolves when stored.
    fn put(&self, key: &str, value: VaultValue) -> VaultUnitRequest;

    /// Get a value by key. Returns a request that resolves with the value.
    fn get(&self, key: &str) -> VaultGetRequest;

    /// Delete a value by key. Returns a request that resolves when deleted.
    fn delete(&self, key: &str) -> VaultUnitRequest;

    /// List keys in the vault, optionally filtered by a prefix. Returns a request yielding a stream of keys.
    fn list(&self, prefix: Option<&str>) -> VaultListRequest;

    /// Change the passphrase. Returns a request that resolves when changed.
    fn change_passphrase(
        &self,
        old_passphrase: &Passphrase,
        new_passphrase: &Passphrase,
    ) -> VaultChangePassphraseRequest;

    /// Save the vault state (if applicable). Returns a request that resolves when saved.
    fn save(&self) -> VaultSaveRequest;

    /// Put a value if the key doesn't exist. Returns a request resolving to true if inserted, false otherwise.
    fn put_if_absent(&self, key: &str, value: VaultValue) -> VaultBoolRequest;

    /// Put multiple entries in the vault. Returns a request that resolves when all are stored.
    fn put_all(&self, entries: Vec<(String, VaultValue)>) -> VaultPutAllRequest;

    /// Find entries matching a pattern. Returns a request yielding a stream of matching key-value pairs.
    fn find(&self, pattern: &str) -> VaultFindRequest;

    /// Optional: Create a new namespace
    fn create_namespace(&self, _namespace: &str) -> VaultUnitRequest {
        let (tx, rx) = oneshot::channel();
        let _ = tx.send(Err(VaultError::UnsupportedOperation(
            "This provider does not support namespaces".to_string(),
        )));
        VaultUnitRequest::new(rx)
    }

    /// Optional: Store a value in a specific namespace
    fn put_with_namespace(
        &self,
        _namespace: &str,
        _key: &str,
        _value: VaultValue,
    ) -> VaultUnitRequest {
        let (tx, rx) = oneshot::channel();
        let _ = tx.send(Err(VaultError::UnsupportedOperation(
            "This provider does not support namespaces".to_string(),
        )));
        VaultUnitRequest::new(rx)
    }

    /// Optional: Get entries in a specific namespace
    fn get_by_namespace(&self, _namespace: &str) -> VaultListRequest {
        let (tx, rx) = mpsc::channel(1);
        let _ = tx.try_send(Err(VaultError::UnsupportedOperation(
            "This provider does not support namespaces".to_string(),
        )));
        VaultListRequest::new(rx)
    }

    /// Optional: Get a single value from a specific namespace
    fn get_from_namespace(&self, _namespace: &str, _key: &str) -> VaultGetRequest {
        let (tx, rx) = oneshot::channel();
        let _ = tx.send(Err(VaultError::UnsupportedOperation(
            "This provider does not support namespaces".to_string(),
        )));
        VaultGetRequest::new(rx)
    }

    /// Optional: Delete a key from a specific namespace
    fn delete_from_namespace(&self, _namespace: &str, _key: &str) -> VaultUnitRequest {
        let (tx, rx) = oneshot::channel();
        let _ = tx.send(Err(VaultError::UnsupportedOperation(
            "This provider does not support namespaces".to_string(),
        )));
        VaultUnitRequest::new(rx)
    }

    /// Optional: Find entries in a specific namespace
    fn find_in_namespace(&self, _namespace: &str, _pattern: &str) -> VaultFindRequest {
        let (tx, rx) = mpsc::channel(1);
        let _ = tx.try_send(Err(VaultError::UnsupportedOperation(
            "This provider does not support namespaces".to_string(),
        )));
        VaultFindRequest::new(rx)
    }

    /// Optional: List all available namespaces
    fn list_namespaces(&self) -> VaultListNamespacesRequest {
        let (tx, rx) = oneshot::channel();
        let _ = tx.send(Err(VaultError::UnsupportedOperation(
            "This provider does not support namespaces".to_string(),
        )));
        VaultListNamespacesRequest::new(rx)
    }

    /// Check if this is a new vault (no existing data)
    fn is_new_vault(&self) -> bool {
        true // Default to true, providers should override
    }
}

/// Alias for a boxed VaultOperation
pub type BoxedVaultOperation = Box<dyn VaultOperation>;

// Passphrase type alias moved higher up
