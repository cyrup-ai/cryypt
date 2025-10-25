//! Cryptographic operations for vault data protection
//!
//! Contains encryption, decryption, key derivation, and secure data handling.

use super::super::LocalVaultProvider;
use crate::error::{VaultError, VaultResult};
use crate::operation::Passphrase;
use cryypt_cipher::Cryypt;
use cryypt_key::api::{MasterKeyBuilder, MasterKeyProvider};
use secrecy::ExposeSecret;
use tokio::fs;
use std::convert::TryInto;
use cryypt_key::api::RsaKeyBuilder;
use rsa::{RsaPrivateKey, RsaPublicKey};
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey};
use hkdf::Hkdf;
use sha2::Sha256;

impl LocalVaultProvider {
    /// Derive encryption key from passphrase using cryypt_key
    pub(crate) async fn derive_encryption_key(
        &self,
        passphrase: &Passphrase,
    ) -> VaultResult<Vec<u8>> {
        log::trace!("Starting passphrase-based key derivation...");

        // Use cryypt_key PassphraseMasterKey for secure key derivation
        let master_key = MasterKeyBuilder::from_passphrase(passphrase.expose_secret());
        let key_bytes = master_key
            .resolve()
            .map_err(|e| VaultError::KeyDerivation(format!("Key derivation failed: {e}")))?;

        log::trace!("Successfully derived {} byte key", key_bytes.len());

        let output_key = key_bytes.to_vec();

        // Store derived key in memory for session
        let mut key_guard = self.encryption_key.lock().await;
        *key_guard = Some(output_key.clone());

        Ok(output_key)
    }

    /// Derive encryption key from RSA private key material using HKDF-SHA256
    ///
    /// This provides deterministic key derivation: same RSA key → same encryption key
    /// 
    /// # Arguments
    /// * `private_key_pkcs1` - RSA private key in PKCS1 DER format (from RsaKeyManager)
    ///
    /// # Returns
    /// 32-byte AES-256 encryption key derived from RSA key material
    pub(crate) async fn derive_encryption_key_from_rsa(
        &self,
        private_key_pkcs1: &[u8],
    ) -> VaultResult<Vec<u8>> {
        log::trace!("Starting RSA-based key derivation...");

        // Use RSA key bytes directly as input key material (IKM) for HKDF
        // No need to parse the key structure - the DER bytes have sufficient entropy
        let hk = Hkdf::<Sha256>::new(None, private_key_pkcs1);
        
        let mut encryption_key = vec![0u8; 32]; // 32 bytes = 256 bits for AES-256-GCM
        hk.expand(b"cryypt-vault-aes-key-v1", &mut encryption_key)
            .map_err(|e| VaultError::KeyDerivation(format!("HKDF expansion failed: {}", e)))?;

        log::trace!("Successfully derived 32-byte encryption key from RSA material");

        // Store derived key in memory for session
        let mut key_guard = self.encryption_key.lock().await;
        *key_guard = Some(encryption_key.clone());

        Ok(encryption_key)
    }

    /// Encrypt data using AES with session key
    pub(crate) async fn encrypt_data(&self, data: &[u8]) -> VaultResult<Vec<u8>> {
        // Get the encryption key from session
        let key_guard = self.encryption_key.lock().await;
        let encryption_key = key_guard.as_ref().ok_or_else(|| VaultError::VaultLocked)?;

        log::trace!(
            "Encrypting {} bytes with {} byte key",
            data.len(),
            encryption_key.len()
        );

        // Use service - single path for all encryption
        let encrypted_data = self.encryption_service.encrypt(data, encryption_key).await?;

        log::trace!(
            "Encryption completed successfully, output: {} bytes",
            encrypted_data.len()
        );
        Ok(encrypted_data)
    }

    /// Decrypt data using AES with session key
    pub(crate) async fn decrypt_data(&self, encrypted_data: &[u8]) -> VaultResult<Vec<u8>> {
        // Get the encryption key from session
        let key_guard = self.encryption_key.lock().await;
        let encryption_key = key_guard.as_ref().ok_or_else(|| VaultError::VaultLocked)?;

        log::trace!(
            "Decrypting {} bytes with {} byte key",
            encrypted_data.len(),
            encryption_key.len()
        );

        // Validate input data before attempting decryption
        if encrypted_data.len() < 32 {
            let error_msg = format!(
                "Invalid encrypted data: too short ({} bytes, minimum 32 required)",
                encrypted_data.len()
            );
            log::error!("{}", error_msg);
            return Err(VaultError::Decryption(error_msg));
        }

        // Use service
        let decrypted_data = self.encryption_service.decrypt(encrypted_data, encryption_key).await?;

        log::trace!(
            "Decryption completed successfully, output: {} bytes",
            decrypted_data.len()
        );
        Ok(decrypted_data)
    }

    /// Get or create salt for key derivation - stored encrypted in SurrealDB
    pub(crate) async fn get_or_create_salt(&self) -> VaultResult<Vec<u8>> {
        use rand::RngCore;

        // Try to retrieve existing salt using natural keys format
        let salt_record_id = super::key_utils::create_record_id("__vault_salt__");
        let query = format!("SELECT * FROM {salt_record_id}");
        let db = self.dao.db();

        let mut result = db
            .query(&query)
            .await
            .map_err(|e| VaultError::Provider(format!("DB query failed: {e}")))?
            .check()
            .map_err(|e| VaultError::Provider(format!("DB check failed: {e}")))?;

        use super::super::VaultEntry;
        let salt_entry: Option<VaultEntry> = result
            .take(0)
            .map_err(|e| VaultError::Provider(format!("DB result take failed: {e}")))?;

        match salt_entry {
            Some(entry) => {
                log::debug!("Found existing encrypted salt in database");

                // Decode salt from base64 with robust error handling - use URL_SAFE_NO_PAD for Argon2 compatibility
                use base64::{
                    Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as BASE64_ARGON2,
                };
                match BASE64_ARGON2.decode(&entry.value) {
                    Ok(salt) => {
                        if salt.len() == 32 {
                            log::debug!("Successfully decoded existing salt from database");
                            Ok(salt)
                        } else {
                            log::warn!(
                                "Salt corrupted: expected exactly 32 bytes, got {}. Generating new salt.",
                                salt.len()
                            );
                            // Generate new salt if existing one is corrupted
                            self.generate_and_store_new_salt().await
                        }
                    }
                    Err(e) => {
                        log::warn!(
                            "Failed to decode existing salt from database ({}). Generating new salt.",
                            e
                        );
                        // Generate new salt if decoding fails
                        self.generate_and_store_new_salt().await
                    }
                }
            }
            None => {
                log::info!("No existing salt found - generating new salt");
                self.generate_and_store_new_salt().await
            }
        }
    }

    /// Generate and store a new salt in the database
    async fn generate_and_store_new_salt(&self) -> VaultResult<Vec<u8>> {
        use rand::RngCore;

        // Generate new salt
        let mut salt = vec![0u8; 32]; // 32 bytes salt
        rand::rng().fill_bytes(&mut salt);

        // Store encrypted salt in database - use URL_SAFE_NO_PAD for Argon2 compatibility
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as BASE64_ARGON2};
        let salt_b64 = BASE64_ARGON2.encode(&salt);

        // Use natural keys format for consistency
        let record_id = super::key_utils::create_record_id("__vault_salt__");
        let upsert_query = format!(
            "UPSERT {} SET value = $value, created_at = $created_at, updated_at = $updated_at",
            record_id
        );

        let db = self.dao.db();
        let now = chrono::Utc::now();
        match db
            .query(upsert_query)
            .bind(("value", salt_b64))
            .bind(("created_at", surrealdb::value::Datetime::from(now)))
            .bind(("updated_at", surrealdb::value::Datetime::from(now)))
            .await
        {
            Ok(_) => {
                log::info!("Generated and stored new encrypted salt in database");
                Ok(salt)
            }
            Err(e) => Err(VaultError::Provider(format!("Failed to store salt: {e}"))),
        }
    }

}
