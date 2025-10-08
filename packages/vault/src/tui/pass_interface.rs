//! Pass password store interface - Simple non-async implementation
//! Following README.md patterns - no async_trait usage

use crate::db::{Document, DocumentDao};
use crate::error::VaultResult;
use std::path::Path;
use std::sync::Arc;
use surrealdb::Surreal;
use surrealdb::engine::any::Any;

/// Pass password store interface (non-async version)
#[derive(Debug)]
pub struct PassInterface {
    dao: DocumentDao,
}

// Note: Default is not implemented - PassInterface requires a database connection
// Use PassInterface::new(db) or PassInterface::from_path() instead

impl PassInterface {
    /// Create a new pass interface
    pub fn new(db: Arc<Surreal<Any>>) -> Self {
        Self {
            dao: DocumentDao::new(db),
        }
    }

    /// Create a new pass interface from path (for compatibility)
    pub async fn from_path<P: AsRef<Path>>(store_path: P) -> VaultResult<Self> {
        // Create SurrealDB connection using the path
        use surrealdb;

        let db_path = store_path.as_ref().join("passwords.db");
        let db_url = format!("surrealkv://{}", db_path.display());

        let db = surrealdb::engine::any::connect(db_url.as_str())
            .await
            .map_err(|e| {
                crate::error::VaultError::Provider(format!("Database connection failed: {e}"))
            })?;

        db.use_ns("passwords").use_db("store").await.map_err(|e| {
            crate::error::VaultError::Provider(format!("Database setup failed: {e}"))
        })?;

        Ok(Self::new(Arc::new(db)))
    }

    /// List all password entries
    pub async fn list(&self) -> VaultResult<Vec<String>> {
        let documents = self
            .dao
            .find_by_tag("password".to_string())
            .await
            .map_err(|e| {
                crate::error::VaultError::Provider(format!(
                    "Failed to find password entries: {}",
                    e
                ))
            })?;
        Ok(documents.into_iter().map(|doc| doc.key).collect())
    }

    /// Get a specific password entry
    pub async fn get(&self, name: &str) -> VaultResult<String> {
        match self.dao.find_by_key(name.to_string()).await.map_err(|e| {
            crate::error::VaultError::Provider(format!("Failed to get password entry: {e}"))
        })? {
            Some(doc) => Ok(doc.content),
            None => Err(crate::error::VaultError::ItemNotFound),
        }
    }

    /// Search for password entries
    pub async fn search(&self, query: &str) -> VaultResult<Vec<String>> {
        let all = self.list().await?;
        Ok(all
            .into_iter()
            .filter(|entry| entry.contains(query))
            .collect())
    }

    /// Insert a new password entry
    pub async fn insert(&self, name: &str, password: &str) -> VaultResult<()> {
        let document = Document {
            id: None,
            key: name.to_string(),
            content: password.to_string(),
            metadata: serde_json::json!({}),
            created_at: None,
            updated_at: None,
            tags: vec!["password".to_string()],
        };

        self.dao.save(document).await.map_err(|e| {
            crate::error::VaultError::Provider(format!("Failed to insert password: {e}"))
        })?;
        Ok(())
    }

    /// Remove a password entry
    pub async fn remove(&self, name: &str) -> VaultResult<()> {
        let deleted = self
            .dao
            .delete_by_key(name.to_string())
            .await
            .map_err(|e| {
                crate::error::VaultError::Provider(format!("Failed to delete password: {e}"))
            })?;

        if deleted {
            Ok(())
        } else {
            Err(crate::error::VaultError::ItemNotFound)
        }
    }
}
