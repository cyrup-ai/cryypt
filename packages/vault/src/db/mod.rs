pub mod dao;
pub mod database;
pub mod document;
pub mod error;
pub mod migrations;
pub mod stream;
pub mod vault_store;

// Re-export what's actually needed - but properly export without unused import warnings
#[allow(unused_imports)]
pub use {
    database::{ConnectionConfig, Dao},
    document::{Document, DocumentDao},
    error::{DatabaseError, DatabaseResult},
    stream::QueryStream,
    vault_store::{LocalVaultProvider, VaultEntry},
};
