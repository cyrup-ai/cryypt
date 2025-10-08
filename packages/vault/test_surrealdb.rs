use surrealdb::Surreal;
use surrealdb::engine::any::Any;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Testing SurrealDB UPSERT behavior...");
    
    // Connect to SurrealKV database
    let db = surrealdb::engine::any::connect("surrealkv://test_debug.db").await?;
    let db = Arc::new(db);
    
    // Use namespace and database
    db.use_ns("vault").use_db("vault").await?;
    
    // Define the table schema (same as vault)
    db.query("
        DEFINE TABLE IF NOT EXISTS vault_entries SCHEMAFULL;
        DEFINE FIELD id ON TABLE vault_entries TYPE record<vault_entries>;
        DEFINE FIELD value ON TABLE vault_entries TYPE string;
        DEFINE FIELD metadata ON TABLE vault_entries TYPE option<object>;
        DEFINE FIELD created_at ON TABLE vault_entries TYPE datetime;
        DEFINE FIELD updated_at ON TABLE vault_entries TYPE datetime;
        DEFINE FIELD expires_at ON TABLE vault_entries TYPE option<datetime>;
        DEFINE FIELD namespace ON TABLE vault_entries TYPE option<string>;
    ").await?;
    
    println!("Schema defined successfully");
    
    // Test UPSERT operation (same as vault)
    let upsert_query = "UPSERT vault_entries:testkey SET value = $value, metadata = $metadata, created_at = $created_at, updated_at = $updated_at, expires_at = $expires_at, namespace = $namespace";
    
    let now = chrono::Utc::now();
    let mut result = db.query(&upsert_query)
        .bind(("value", "Hello World"))
        .bind(("metadata", None::<serde_json::Value>))
        .bind(("created_at", surrealdb::value::Datetime::from(now)))
        .bind(("updated_at", surrealdb::value::Datetime::from(now)))
        .bind(("expires_at", None::<surrealdb::value::Datetime>))
        .bind(("namespace", None::<String>))
        .await?;
        
    let created: Vec<serde_json::Value> = result.take(0)?;
    println!("UPSERT result: {:?}", created);
    
    // Test SELECT operation (same as vault)
    let select_query = "SELECT * FROM vault_entries:testkey";
    let mut result = db.query(&select_query).await?;
    let selected: Option<serde_json::Value> = result.take(0)?;
    println!("SELECT result: {:?}", selected);
    
    // Test LIST operation (same as vault)
    let list_query = "SELECT id FROM vault_entries";
    let mut result = db.query(&list_query).await?;
    let listed: Vec<serde_json::Value> = result.take(0)?;
    println!("LIST result: {:?}", listed);
    
    Ok(())
}