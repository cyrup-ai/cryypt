use crate::error::VaultResult;
use std::path::Path;
use std::sync::{Arc, Mutex, LazyLock};
use surrealdb::{engine::local::{Db, SurrealKv}, Surreal};
use crate::db::migrations;

// Use Arc<Mutex<>> for thread-safe global access with mutability
static DB: LazyLock<Arc<Mutex<Option<Surreal<Db>>>>> = LazyLock::new(|| {
    let db = Surreal::init();
    Arc::new(Mutex::new(Some(db)))
});

/// Database Access Object for managing database connections and operations
#[derive(Clone)]
pub struct Dao {
    db: Arc<Surreal<Db>>,
}

impl Dao {
    /// Helper function to extract data from SurrealDB response
    pub fn extract_data<T>(&self, mut response: surrealdb::Response) -> VaultResult<Vec<T>> 
    where 
        T: serde::de::DeserializeOwned
    {
        let result = response.take((0, ""))?;
        Ok(result)
    }

    /// Create a new DAO instance
    pub fn new() -> Self {
        let db = match DB.lock().unwrap().take() {
            Some(db) => db,
            None => Surreal::init(),
        };
        
        // Put it back for future use
        *DB.lock().unwrap() = Some(db.clone());
        
        Self { db: Arc::new(db) }
    }

    /// Get the database connection
    pub fn get_db(&self) -> Arc<Surreal<Db>> {
        self.db.clone()
    }

    /// Initialize a database from a specific file path
    pub async fn initialize_from_path(&mut self, db_path: impl AsRef<Path>) -> VaultResult<()> {
        // Create parent directory if it doesn't exist
        if let Some(parent) = db_path.as_ref().parent() {
            if !parent.exists() {
                std::fs::create_dir_all(parent)?;
            }
        }

        // Database name from filename
        let db_name = db_path
            .as_ref()
            .file_stem()
            .and_then(|n| n.to_str())
            .unwrap_or("cysec");

        println!("Initializing database at: {}", db_path.as_ref().display());

        // Initialize with SurrealKv backend - using clone to avoid mutable reference issues
        let new_db = Surreal::new::<SurrealKv>(db_path.as_ref()).await?;
        
        // Make a new connection with the initialized db
        let new_db_arc = Arc::new(new_db);

        // Use standard namespace and database name
        new_db_arc.use_ns("vault").use_db(db_name).await?;
        
        // Replace our local db with the new one
        self.db = new_db_arc.clone();

        // Always try to run migrations for new database setup
        println!("🔄 Checking database schema...");

        // Run migrations (creates tables if they don't exist)
        if let Err(e) = migrations::run_migrations(&self.db).await {
            eprintln!("⚠️ Warning: Migration error: {}. Basic functionality may still work.", e);
        } else {
            println!("✅ Database schema is ready");
        }

        Ok(())
    }
}