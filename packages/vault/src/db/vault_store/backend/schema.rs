//! Database schema initialization for vault storage
//!
//! Contains schema definition and initialization logic for SurrealDB vault tables.

use super::super::LocalVaultProvider;
use crate::db::dao::Error as DaoError;

impl LocalVaultProvider {
    /// Initialize the vault schema (specific to this provider)
    pub async fn initialize_schema(&self) -> Result<(), DaoError> {
        let db = self.dao.db();

        // Define vault entries table
        db.query(
            "
            DEFINE TABLE IF NOT EXISTS vault_entries SCHEMAFULL;
            DEFINE FIELD id ON TABLE vault_entries TYPE record<vault_entries>;
            DEFINE FIELD value ON TABLE vault_entries TYPE string;
            DEFINE FIELD metadata ON TABLE vault_entries TYPE option<object>;
            DEFINE FIELD created_at ON TABLE vault_entries TYPE datetime;
            DEFINE FIELD updated_at ON TABLE vault_entries TYPE datetime;
            DEFINE FIELD expires_at ON TABLE vault_entries TYPE option<datetime>;
            DEFINE FIELD namespace ON TABLE vault_entries TYPE option<string>;
            ",
        )
        .await
        .map_err(|e| DaoError::Database(e.to_string()))?;

        // Define vault_config table for RSA key configuration
        db.query(
            "
            DEFINE TABLE IF NOT EXISTS vault_config SCHEMAFULL;
            DEFINE FIELD rsa_key_path ON TABLE vault_config TYPE string;
            DEFINE FIELD rsa_public_key_spki ON TABLE vault_config TYPE string;
            DEFINE FIELD created_at ON TABLE vault_config TYPE datetime;
            DEFINE FIELD updated_at ON TABLE vault_config TYPE datetime;
            ",
        )
        .await
        .map_err(|e| DaoError::Database(e.to_string()))?;

        // Define JWT sessions table for secure session persistence
        db.query(
            "
            DEFINE TABLE IF NOT EXISTS jwt_sessions SCHEMAFULL;
            DEFINE FIELD vault_path_hash ON TABLE jwt_sessions TYPE string;
            DEFINE FIELD session_token_encrypted ON TABLE jwt_sessions TYPE string;
            DEFINE FIELD encryption_salt ON TABLE jwt_sessions TYPE string;
            DEFINE FIELD created_at ON TABLE jwt_sessions TYPE datetime;
            DEFINE FIELD expires_at ON TABLE jwt_sessions TYPE datetime;
            DEFINE FIELD last_accessed ON TABLE jwt_sessions TYPE datetime;
            
            DEFINE INDEX jwt_sessions_vault_hash ON TABLE jwt_sessions COLUMNS vault_path_hash UNIQUE;
            DEFINE INDEX jwt_sessions_expires ON TABLE jwt_sessions COLUMNS expires_at;
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
