//! Database schema initialization for vault storage
//!
//! Contains schema definition and initialization logic for SurrealDB vault tables.

use super::super::LocalVaultProvider;
use crate::db::dao::Error as DaoError;

impl LocalVaultProvider {
    /// Initialize the vault schema (specific to this provider)
    pub async fn initialize_schema(&self) -> Result<(), DaoError> {
        // Define vault entries table
        let db = self.dao.db();
        db.query(
            "
            DEFINE TABLE IF NOT EXISTS vault_entries SCHEMAFULL;
            DEFINE FIELD key ON TABLE vault_entries TYPE string;
            DEFINE FIELD value ON TABLE vault_entries TYPE string;
            DEFINE FIELD created_at ON TABLE vault_entries TYPE datetime;
            DEFINE FIELD updated_at ON TABLE vault_entries TYPE datetime;
            DEFINE FIELD expires_at ON TABLE vault_entries TYPE option<datetime>;
            DEFINE FIELD namespace ON TABLE vault_entries TYPE option<string>;
            DEFINE INDEX vault_key ON TABLE vault_entries COLUMNS key UNIQUE;
        ",
        )
        .await
        .map_err(|e| DaoError::Database(e.to_string()))?;

        Ok(())
    }

    /// Creates a new namespace for vault entries
    pub async fn create_namespace(&self, namespace: String) -> Result<(), DaoError> {
        // Define namespace in SurrealDB
        let query = "DEFINE NAMESPACE $namespace";
        let db = self.dao.db();

        db.query(query)
            .bind(("namespace", namespace))
            .await
            .map_err(|e| DaoError::Database(e.to_string()))?;

        Ok(())
    }
}
