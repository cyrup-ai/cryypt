use crate::core::VaultValue;

/// Response for unlock operations
#[derive(Debug)]
pub struct UnlockResponse();

/// Response for lock operations
#[derive(Debug)]
pub struct LockResponse();

/// Response for put operations
#[derive(Debug)]
pub struct PutResponse();

/// Response for get operations
#[derive(Debug)]
pub struct GetResponse {
    /// Retrieved value
    pub value: VaultValue,
}

/// Response for delete operations
#[derive(Debug)]
pub struct DeleteResponse();

/// Response for put-if-absent operations
#[derive(Debug)]
pub struct PutIfAbsentResponse {
    /// Whether the value was inserted (true) or already existed (false)
    pub inserted: bool,
}

/// Response for put-all operations
#[derive(Debug)]
pub struct PutAllResponse();

/// Response for find operations
#[derive(Debug)]
pub struct FindResponse {
    /// Found entries
    pub entries: Vec<(String, VaultValue)>,
}

/// Response for list operations
#[derive(Debug)]
pub struct ListResponse {
    /// List of keys
    pub keys: Vec<String>,
}

/// Response for save operations
#[derive(Debug)]
pub struct SaveResponse();

/// Response for change-passphrase operations
#[derive(Debug)]
pub struct ChangePassphraseResponse();
