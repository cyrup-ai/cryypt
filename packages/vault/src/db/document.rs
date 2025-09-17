use crate::db::dao::{Error, SurrealDbDao, TableType};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use surrealdb::Surreal;
use surrealdb::engine::any::Any;
// Add additional imports if needed
use chrono::{DateTime, Utc};
use futures::StreamExt;
use uuid::Uuid;

/// Document stored in the vault database
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Document {
    /// Unique identifier
    pub id: Option<String>,
    /// Document key/path
    pub key: String,
    /// Document content
    pub content: String,
    /// Document metadata (JSON)
    pub metadata: serde_json::Value,
    /// Creation timestamp
    pub created_at: Option<DateTime<Utc>>,
    /// Last modification timestamp
    pub updated_at: Option<DateTime<Utc>>,
    /// Optional tags for categorization
    pub tags: Vec<String>,
}

/// Data Access Object for Document entities
#[derive(Debug, Clone)]
pub struct DocumentDao {
    dao: SurrealDbDao<Document>,
}

impl DocumentDao {
    /// Create a new DocumentDao
    pub fn new(db: Arc<Surreal<Any>>) -> Self {
        Self {
            dao: SurrealDbDao::new(db, "documents", TableType::Document),
        }
    }

    /// Save a document to the database
    pub async fn save(&self, document: Document) -> Result<Document, Error> {
        let mut doc = document;

        // Set timestamps if not present
        let now = Utc::now();
        if doc.created_at.is_none() {
            doc.created_at = Some(now);
        }
        doc.updated_at = Some(now);

        // Generate ID from key if not present
        if doc.id.is_none() {
            doc.id = Some(format!("doc:{}", Uuid::new_v4()));
        }

        // Create or update based on id existence
        if let Some(id) = &doc.id {
            let mut stream = self.dao.update(id, doc.clone());
            let mut items = Vec::new();

            while let Some(result) = stream.next().await {
                match result {
                    Ok(item) => items.push(item),
                    Err(e) => return Err(e),
                }
            }

            if let Some(updated) = items.first() {
                Ok(updated.clone())
            } else {
                Err(Error::Database("Failed to update document".into()))
            }
        } else {
            let mut stream = self.dao.create(doc.clone());
            let mut items = Vec::new();

            while let Some(result) = stream.next().await {
                match result {
                    Ok(item) => items.push(item),
                    Err(e) => return Err(e),
                }
            }

            if let Some(created) = items.first() {
                Ok(created.clone())
            } else {
                Err(Error::Database("Failed to create document".into()))
            }
        }
    }

    /// Find a document by its key
    pub async fn find_by_key(&self, key: String) -> Result<Option<Document>, Error> {
        let query = "SELECT * FROM documents WHERE key = $key LIMIT 1".to_string();
        let db = self.dao.db();

        let mut result = db
            .query(query)
            .bind(("key", key))
            .await
            .map_err(|e| Error::Database(e.to_string()))?;

        let docs: Vec<Document> = result.take(0).map_err(|e| Error::Database(e.to_string()))?;

        Ok(docs.into_iter().next())
    }

    /// Find documents by tag
    pub async fn find_by_tag(&self, tag: String) -> Result<Vec<Document>, Error> {
        let query = "SELECT * FROM documents WHERE $tag IN tags".to_string();
        let db = self.dao.db();

        let mut result = db
            .query(query)
            .bind(("tag", tag))
            .await
            .map_err(|e| Error::Database(e.to_string()))?;

        let docs: Vec<Document> = result.take(0).map_err(|e| Error::Database(e.to_string()))?;

        Ok(docs)
    }

    /// Delete a document by its key
    pub async fn delete_by_key(&self, key: String) -> Result<bool, Error> {
        // First find the document to get its ID
        if let Some(doc) = self.find_by_key(key).await?
            && let Some(id) = doc.id
        {
            let mut stream = self.dao.delete(&id);
            let mut items = Vec::new();

            while let Some(result) = stream.next().await {
                match result {
                    Ok(item) => items.push(item),
                    Err(e) => return Err(e),
                }
            }

            if !items.is_empty() {
                return Ok(true);
            }
        }

        Ok(false)
    }

    /// List all documents
    pub async fn list_all(&self) -> Result<Vec<Document>, Error> {
        let mut stream = self.dao.find_all();
        let mut items = Vec::new();

        while let Some(result) = stream.next().await {
            match result {
                Ok(item) => items.push(item),
                Err(e) => return Err(e),
            }
        }

        Ok(items)
    }

    /// Find documents matching a pattern
    pub async fn find_by_pattern(&self, pattern: String) -> Result<Vec<Document>, Error> {
        let query = "SELECT * FROM documents WHERE key LIKE $pattern".to_string();
        let db = self.dao.db();
        let pattern = format!("%{}%", pattern);

        let mut result = db
            .query(query)
            .bind(("pattern", pattern))
            .await
            .map_err(|e| Error::Database(e.to_string()))?;

        let docs: Vec<Document> = result.take(0).map_err(|e| Error::Database(e.to_string()))?;

        Ok(docs)
    }
}
