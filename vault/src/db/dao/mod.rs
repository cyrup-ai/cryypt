//! Database Access Object (DAO) module
//!
//! Provides trait definitions and base types for database operations
//! with SurrealDB backend support.

use chrono::{DateTime, Utc};
use futures::Stream;
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::pin::Pin;
use std::sync::Arc;
use surrealdb::Surreal;
use surrealdb::engine::any::Any;
use thiserror::Error;

// Import individual implementations
mod documents;
mod queries;

// Import query helpers for trait default implementations
use queries::{default_find_by_relation, default_join};

// Re-export implementations
pub use documents::SurrealDbDao;

/// Database operation error
#[derive(Debug, Error)]
pub enum Error {
    #[error("Database error: {0}")]
    Database(String),
    #[error("Item not found")]
    NotFound,
    #[error("Invalid ID format")]
    InvalidId,
    #[error("Serialization error: {0}")]
    Serialization(String),
    #[error("Invalid input: {0}")]
    InvalidInput(String),
    #[error("Conflict: {0}")]
    Conflict(String),
    #[error("Other error: {0}")]
    Other(String),
}

// Implement From<surrealdb::Error> for Error so we can use the ? operator
impl From<surrealdb::Error> for Error {
    fn from(err: surrealdb::Error) -> Self {
        Error::Database(err.to_string())
    }
}

/// Represents a SurrealDB table type
#[derive(Debug, Clone)]
pub enum TableType {
    /// Regular document table
    Document,
    /// Relational table with foreign key constraints
    Relational(Vec<ForeignKey>),
    /// Edge table for graph relationships
    Edge { in_table: String, out_table: String },
    /// Table with vector embeddings
    Vector { analyzer: String, dimension: usize },
    /// Time series table
    TimeSeries { time_field: String },
}

/// Foreign key constraint definition
#[derive(Debug, Clone)]
pub struct ForeignKey {
    /// Name of the field that references another table
    pub field: String,
    /// Referenced table name
    pub references_table: String,
    /// Referenced field name (usually 'id')
    pub references_field: String,
    /// What to do on delete
    pub on_delete: ForeignKeyAction,
}

/// Foreign key action on delete
#[derive(Debug, Clone)]
pub enum ForeignKeyAction {
    /// Cascade delete related records
    Cascade,
    /// Set field to null
    SetNull,
    /// Restrict deletion if related records exist
    Restrict,
}

/// Generic DAO trait for SurrealDB operations
pub trait GenericDao<T>: Send + Sync + Sized + 'static
where
    T: Serialize + DeserializeOwned + Send + Sync + 'static,
{
    fn table_name(&self) -> &str;
    fn table_type(&self) -> &TableType;
    fn db(&self) -> &Arc<Surreal<Any>>;

    /// Create a new record
    fn create<'life0, 'fut>(
        &'life0 self,
        doc: T,
    ) -> Pin<Box<dyn Stream<Item = Result<T, Error>> + Send + 'fut>>
    where
        'life0: 'fut;

    /// Find record by ID
    fn find_by_id<'life0, 'life1, 'fut>(
        &'life0 self,
        id: &'life1 str,
    ) -> Pin<Box<dyn Stream<Item = Result<T, Error>> + Send + 'fut>>
    where
        'life0: 'fut,
        'life1: 'fut;

    /// Find all records
    fn find_all<'life0, 'fut>(
        &'life0 self,
    ) -> Pin<Box<dyn Stream<Item = Result<T, Error>> + Send + 'fut>>
    where
        'life0: 'fut;

    /// Update record by ID
    fn update<'life0, 'life1, 'fut>(
        &'life0 self,
        id: &'life1 str,
        doc: T,
    ) -> Pin<Box<dyn Stream<Item = Result<T, Error>> + Send + 'fut>>
    where
        'life0: 'fut,
        'life1: 'fut;

    /// Delete record by ID
    fn delete<'life0, 'life1, 'fut>(
        &'life0 self,
        id: &'life1 str,
    ) -> Pin<Box<dyn Stream<Item = Result<T, Error>> + Send + 'fut>>
    where
        'life0: 'fut,
        'life1: 'fut;

    /// Create a graph relationship
    fn relate<'life0, 'life1, 'life2, 'fut>(
        &'life0 self,
        from_id: &'life1 str,
        relation: &'life2 str,
        to_id: &'life1 str,
    ) -> Pin<Box<dyn Stream<Item = Result<T, Error>> + Send + 'fut>>
    where
        'life0: 'fut,
        'life1: 'fut,
        'life2: 'fut;

    /// Find records by vector similarity
    fn find_similar<'life0, 'fut>(
        &'life0 self,
        doc: &T,
    ) -> Pin<Box<dyn Stream<Item = Result<T, Error>> + Send + 'fut>>
    where
        'life0: 'fut;

    /// Query time series data
    fn query_time_range<'life0, 'fut>(
        &'life0 self,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
    ) -> Pin<Box<dyn Stream<Item = Result<T, Error>> + Send + 'fut>>
    where
        'life0: 'fut;

    /// Find records by foreign key relationship
    fn find_by_relation<'life0, 'life1, 'life2, 'fut>(
        &'life0 self,
        relation: &'life1 str,
        target_id: &'life2 str,
    ) -> Pin<Box<dyn Stream<Item = Result<T, Error>> + Send + 'fut>>
    where
        'life0: 'fut,
        'life1: 'fut,
        'life2: 'fut,
    {
        default_find_by_relation(self, relation, target_id)
    }

    /// Join with another table
    fn join<'life0, 'life1, 'life2, 'fut>(
        &'life0 self,
        other_table: &'life1 str,
        join_field: &'life2 str,
    ) -> Pin<Box<dyn Stream<Item = Result<T, Error>> + Send + 'fut>>
    where
        'life0: 'fut,
        'life1: 'fut,
        'life2: 'fut,
    {
        default_join(self, other_table, join_field)
    }
}
