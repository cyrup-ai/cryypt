use crate::db::error::{DatabaseError, DatabaseResult};
use crate::db::migrations;
use crate::error::VaultResult;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use surrealdb::{
    Surreal,
    engine::any::{Any, connect},
};
use tokio::time::{sleep, timeout};
use tracing::{debug, error, info, warn};

// Global database instance - removed per guidelines
#[allow(dead_code)]
static DB: LazyLock<Arc<Option<Surreal<Any>>>> = LazyLock::new(|| Arc::new(None));

/// Connection configuration for database
#[derive(Clone, Debug)]
pub struct ConnectionConfig {
    pub max_retries: u32,
    pub connection_timeout: Duration,
    pub retry_delay: Duration,
    pub health_check_interval: Duration,
}

impl Default for ConnectionConfig {
    fn default() -> Self {
        Self {
            max_retries: 3,
            connection_timeout: Duration::from_secs(30),
            retry_delay: Duration::from_millis(1000),
            health_check_interval: Duration::from_secs(60),
        }
    }
}

/// Database Access Object for managing database connections and operations
#[derive(Clone)]
pub struct Dao {
    db: Arc<Surreal<Any>>,
    config: ConnectionConfig,
    last_health_check_timestamp: Arc<AtomicU64>,
}

impl Default for Dao {
    fn default() -> Self {
        Self::new()
    }
}

impl Dao {
    /// Helper function to extract data from SurrealDB response
    pub fn extract_data<T>(&self, mut response: surrealdb::Response) -> VaultResult<Vec<T>>
    where
        T: serde::de::DeserializeOwned,
    {
        let result = response.take((0, ""))?;
        Ok(result)
    }

    /// Create a new DAO instance with default configuration
    pub fn new() -> Self {
        Self::with_config(ConnectionConfig::default())
    }

    /// Create a new DAO instance with custom configuration
    pub fn with_config(config: ConnectionConfig) -> Self {
        Self {
            db: Arc::new(Surreal::init()),
            config,
            last_health_check_timestamp: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Get the database connection
    pub fn get_db(&self) -> Arc<Surreal<Any>> {
        self.db.clone()
    }

    /// Initialize a database from a specific file path with retry logic
    pub async fn initialize_from_path(&mut self, db_path: impl AsRef<Path>) -> DatabaseResult<()> {
        let path = db_path.as_ref();

        // Create parent directory if it doesn't exist
        if let Some(parent) = path.parent()
            && !parent.exists()
        {
            std::fs::create_dir_all(parent).map_err(|e| DatabaseError::IoError { error: e })?;
        }

        // Database name from filename - zero allocation approach
        let db_name = path.file_stem().and_then(|n| n.to_str()).unwrap_or("cysec");

        info!(
            path = %path.display(),
            db_name = db_name,
            "Initializing database with retry logic"
        );

        // Initialize connection with retry logic
        let new_db = self.connect_with_retry(path, db_name).await?;
        self.db = Arc::new(new_db);

        // Run migrations with retry
        self.run_migrations_with_retry().await?;

        // Update health check timestamp - lock-free atomic operation
        let timestamp = match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(duration) => duration.as_secs(),
            Err(_) => 0,
        };
        self.last_health_check_timestamp
            .store(timestamp, Ordering::Relaxed);

        info!("Database initialization completed successfully");
        Ok(())
    }

    /// Connect to database with retry logic - zero allocation
    async fn connect_with_retry(
        &self,
        db_path: &Path,
        db_name: &str,
    ) -> DatabaseResult<Surreal<Any>> {
        // Pre-allocate connection string to avoid repeated allocations
        let mut connection_string = String::with_capacity(64);
        connection_string.push_str("file://");
        connection_string.push_str(&db_path.display().to_string());

        for attempt in 1..=self.config.max_retries {
            debug!(
                attempt,
                max_retries = self.config.max_retries,
                "Attempting database connection"
            );

            match timeout(self.config.connection_timeout, connect(&connection_string)).await {
                Ok(Ok(db)) => {
                    // Set namespace and database
                    if let Err(e) = db.use_ns("vault").use_db(db_name).await {
                        warn!(error = %e, "Failed to set namespace/database, retrying");
                        if attempt < self.config.max_retries {
                            sleep(self.config.retry_delay).await;
                            continue;
                        }
                        return Err(DatabaseError::NamespaceError {
                            namespace: format!("vault/{}", db_name),
                            error: e.to_string(),
                        });
                    }

                    info!(attempt, "Database connection established successfully");
                    return Ok(db);
                }
                Ok(Err(e)) => {
                    warn!(attempt, error = %e, "Database connection failed");
                    if attempt < self.config.max_retries {
                        sleep(self.config.retry_delay).await;
                        continue;
                    }
                    return Err(DatabaseError::ConnectionFailed {
                        message: e.to_string(),
                    });
                }
                Err(_) => {
                    warn!(
                        attempt,
                        timeout_ms = self.config.connection_timeout.as_millis(),
                        "Database connection timeout"
                    );
                    if attempt < self.config.max_retries {
                        sleep(self.config.retry_delay).await;
                        continue;
                    }
                    return Err(DatabaseError::ConnectionTimeout {
                        timeout_ms: self.config.connection_timeout.as_millis() as u64,
                    });
                }
            }
        }

        Err(DatabaseError::RetryLimitExceeded {
            operation: "database_connection".to_string(),
            attempts: self.config.max_retries,
        })
    }

    /// Run migrations with retry logic
    async fn run_migrations_with_retry(&self) -> DatabaseResult<()> {
        info!("Running database migrations");

        for attempt in 1..=self.config.max_retries {
            match migrations::run_migrations(&self.db).await {
                Ok(_) => {
                    info!("Database migrations completed successfully");
                    return Ok(());
                }
                Err(e) => {
                    warn!(attempt, error = %e, "Migration failed");
                    if attempt < self.config.max_retries {
                        sleep(self.config.retry_delay).await;
                        continue;
                    }
                    return Err(DatabaseError::MigrationFailed {
                        migration_name: "schema_setup".to_string(),
                        error: e.to_string(),
                    });
                }
            }
        }

        Err(DatabaseError::RetryLimitExceeded {
            operation: "database_migrations".to_string(),
            attempts: self.config.max_retries,
        })
    }

    /// Perform health check on database connection
    pub async fn health_check(&self) -> DatabaseResult<()> {
        debug!("Performing database health check");

        // Simple query to test connection
        match self.db.query("SELECT 1 as health").await {
            Ok(_) => {
                debug!("Database health check passed");

                // Update last health check timestamp - lock-free atomic operation
                let timestamp = match SystemTime::now().duration_since(UNIX_EPOCH) {
                    Ok(duration) => duration.as_secs(),
                    Err(_) => 0,
                };
                self.last_health_check_timestamp
                    .store(timestamp, Ordering::Relaxed);

                Ok(())
            }
            Err(e) => {
                error!(error = %e, "Database health check failed");
                Err(DatabaseError::HealthCheckFailed {
                    check_name: "connection_test".to_string(),
                    reason: e.to_string(),
                })
            }
        }
    }

    /// Check if health check is needed based on interval - lock-free
    pub fn needs_health_check(&self) -> bool {
        let last_check_timestamp = self.last_health_check_timestamp.load(Ordering::Relaxed);
        if last_check_timestamp == 0 {
            return true; // Never checked
        }

        let current_timestamp = match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(duration) => duration.as_secs(),
            Err(_) => return true, // Assume check needed on time error
        };

        let elapsed = current_timestamp.saturating_sub(last_check_timestamp);
        elapsed > self.config.health_check_interval.as_secs()
    }

    /// Reconnect to database if connection is lost
    pub async fn reconnect(&mut self, db_path: impl AsRef<Path>) -> DatabaseResult<()> {
        warn!("Attempting to reconnect to database");

        let path = db_path.as_ref();
        let db_name = path.file_stem().and_then(|n| n.to_str()).unwrap_or("cysec");

        // Attempt reconnection
        let new_db = self.connect_with_retry(path, db_name).await?;
        self.db = Arc::new(new_db);

        info!("Database reconnection successful");
        Ok(())
    }
}
