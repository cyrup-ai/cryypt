pub mod dao;
pub mod db;
pub mod document;
pub mod migrations;
pub mod stream;
pub mod vault_store;

// Re-export what's actually needed - but properly export without unused import warnings
#[allow(unused_imports)]
pub use {
    db::Dao,
    document::Document,
    document::DocumentDao,
    stream::QueryStream,
    vault_store::SurrealDbVaultProvider,
    vault_store::VaultEntry,
};