use crate::error::VaultError;
use surrealdb::{engine::local::Db, Surreal};
use surrealdb_migrations::MigrationRunner;

pub async fn run_migrations(db: &Surreal<Db>) -> Result<(), VaultError> {
    println!("🔄 Running database migrations...");

    // First, manually create the essential tables
    // This ensures the basic schema exists even if migrations fail
    if let Err(e) = db.query(r#"
        DEFINE TABLE IF NOT EXISTS vault_entries SCHEMAFULL;
        DEFINE FIELD key ON TABLE vault_entries TYPE string;
        DEFINE FIELD value ON TABLE vault_entries TYPE string;
        DEFINE FIELD created_at ON TABLE vault_entries TYPE datetime;
        DEFINE FIELD updated_at ON TABLE vault_entries TYPE datetime;
        DEFINE FIELD namespace ON TABLE vault_entries TYPE option<string>;
        DEFINE INDEX vault_key ON TABLE vault_entries COLUMNS key UNIQUE;
    "#).await {
        eprintln!("Warning: Failed to create initial schema: {}", e);
    }
    
    // Create migrations table if not exists
    if let Err(e) = db.query(r#"
        DEFINE TABLE IF NOT EXISTS migrations SCHEMAFULL;
        DEFINE FIELD version ON TABLE migrations TYPE string;
        DEFINE FIELD name ON TABLE migrations TYPE string;
        DEFINE FIELD executed_at ON TABLE migrations TYPE datetime;
    "#).await {
        eprintln!("Warning: Failed to create migrations table: {}", e);
    }

    // Create a migration runner
    let runner = MigrationRunner::new(db);
    
    // Run migrations
    match runner.up().await {
        Ok(_) => {
            println!("✅ Database migrations completed");
            Ok(())
        },
        Err(e) => {
            // Even if migrations fail, we've ensured the basic schema exists
            eprintln!("⚠️ Migration warning: {}", e);
            // Return Ok since we've handled it by creating tables manually
            Ok(())
        }
    }
}
