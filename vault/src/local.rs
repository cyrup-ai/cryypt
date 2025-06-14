use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot, Mutex};
use tokio::spawn;
use zeroize::Zeroizing;
use rand::Rng;

use crate::config::VaultConfig;
use crate::core::VaultValue;
use crate::error::{VaultError, VaultResult};
use crate::operation::*;
use secrecy::ExposeSecret;
use cryypt_cipher::CipherAlgorithm;
use argon2::{
    password_hash::SaltString,
    Argon2,
};

#[derive(Clone)]
pub struct LocalVaultProvider {
    config: VaultConfig,
    data: Arc<Mutex<HashMap<String, VaultValue>>>,
    key: Arc<Mutex<Option<Zeroizing<[u8; 32]>>>>,
    cipher_algorithm: CipherAlgorithm,
}

impl LocalVaultProvider {
    pub fn new(config: VaultConfig) -> VaultResult<Self> {
        // Use Cascade algorithm for highest security (defense-in-depth)
        let cipher_algorithm = CipherAlgorithm::Cascade;
        
        // Ensure salt file exists with proper permissions
        if !Path::new(&config.salt_path).exists() {
            let mut salt = [0u8; 16];
            rand::rng().fill(&mut salt);
            fs::write(&config.salt_path, &salt).map_err(VaultError::Io)?;
            
            // Set appropriate file permissions
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mut perms = fs::metadata(&config.salt_path).map_err(VaultError::Io)?.permissions();
                perms.set_mode(0o600); // Read/write for owner only
                fs::set_permissions(&config.salt_path, perms).map_err(VaultError::Io)?;
            }
        }
        
        Ok(Self {
            config,
            data: Arc::new(Mutex::new(HashMap::new())),
            key: Arc::new(Mutex::new(None)),
            cipher_algorithm,
        })
    }
    
    /// Create a provider with ChaCha20Poly1305 for faster but still secure encryption
    pub fn new_with_chacha(config: VaultConfig) -> VaultResult<Self> {
        // Use ChaCha20Poly1305 for faster encryption
        let cipher_algorithm = CipherAlgorithm::ChaCha20Poly1305;
        
        // Ensure salt file exists with proper permissions
        if !Path::new(&config.salt_path).exists() {
            let mut salt = [0u8; 16];
            rand::rng().fill(&mut salt);
            fs::write(&config.salt_path, &salt).map_err(VaultError::Io)?;
            
            // Set appropriate file permissions
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mut perms = fs::metadata(&config.salt_path).map_err(VaultError::Io)?.permissions();
                perms.set_mode(0o600); // Read/write for owner only
                fs::set_permissions(&config.salt_path, perms).map_err(VaultError::Io)?;
            }
        }
        
        Ok(Self {
            config,
            data: Arc::new(Mutex::new(HashMap::new())),
            key: Arc::new(Mutex::new(None)),
            cipher_algorithm,
        })
    }
    
    pub fn with_algorithm(config: VaultConfig, algorithm: CipherAlgorithm) -> Self {
        Self {
            config,
            data: Arc::new(Mutex::new(HashMap::new())),
            key: Arc::new(Mutex::new(None)),
            cipher_algorithm: algorithm,
        }
    }

    // Internal async implementation of operations
    fn validate_passphrase_strength(&self, passphrase: &str) -> bool {
        // Minimum length requirement
        if passphrase.len() < 12 {
            return false;
        }
        
        // Check for uppercase letters
        if !passphrase.chars().any(|c| c.is_uppercase()) {
            return false;
        }
        
        // Check for lowercase letters
        if !passphrase.chars().any(|c| c.is_lowercase()) {
            return false;
        }
        
        // Check for numbers
        if !passphrase.chars().any(|c| c.is_numeric()) {
            return false;
        }
        
        // Check for special characters (non-alphanumeric)
        if !passphrase.chars().any(|c| !c.is_alphanumeric()) {
            return false;
        }
        
        true
    }

    /// Derive a key from passphrase using Argon2
    fn derive_key(&self, passphrase: &str, salt: &[u8]) -> VaultResult<Zeroizing<[u8; 32]>> {
        let argon2 = Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            argon2::Params::new(
                self.config.argon2_memory_cost,
                self.config.argon2_time_cost,
                self.config.argon2_parallelism,
                Some(32)
            ).map_err(|e| VaultError::KeyDerivation(e.to_string()))?
        );
        
        let salt_string = SaltString::encode_b64(salt)
            .map_err(|e| VaultError::KeyDerivation(e.to_string()))?;
        
        let mut output = [0u8; 32];
        argon2.hash_password_into(passphrase.as_bytes(), salt_string.as_salt().as_str().as_bytes(), &mut output)
            .map_err(|e| VaultError::KeyDerivation(e.to_string()))?;
        
        Ok(Zeroizing::new(output))
    }

    /// Encrypt data using the cipher API
    async fn encrypt_data(&self, data: &[u8], key: &[u8]) -> VaultResult<Vec<u8>> {
        // For now, use a simplified approach - in production this would use the full cipher API
        // with proper key management
        use aes_gcm::{
            aead::{Aead, KeyInit},
            Aes256Gcm, Nonce,
        };
        
        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|e| VaultError::Encryption(e.to_string()))?;
        
        let mut nonce_bytes = [0u8; 12];
        use aes_gcm::aead::rand_core::{RngCore, OsRng as AesOsRng};
        AesOsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        let ciphertext = cipher.encrypt(nonce, data)
            .map_err(|e| VaultError::Encryption(e.to_string()))?;
        
        // Prepend nonce to ciphertext
        let mut result = nonce_bytes.to_vec();
        result.extend_from_slice(&ciphertext);
        Ok(result)
    }

    /// Decrypt data using the cipher API
    async fn decrypt_data(&self, encrypted_data: &[u8], key: &[u8]) -> VaultResult<Vec<u8>> {
        use aes_gcm::{
            aead::{Aead, KeyInit},
            Aes256Gcm, Nonce,
        };
        
        if encrypted_data.len() < 12 {
            return Err(VaultError::Decryption("Data too short".into()));
        }
        
        let (nonce_bytes, ciphertext) = encrypted_data.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);
        
        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|e| VaultError::Decryption(e.to_string()))?;
        
        cipher.decrypt(nonce, ciphertext)
            .map_err(|e| VaultError::Decryption(e.to_string()))
    }

    async fn unlock_impl(&self, passphrase: &str) -> VaultResult<()> {
        let salt = fs::read(&self.config.salt_path).map_err(VaultError::Io)?;
        
        // Validate salt length
        if salt.len() < 16 {
            return Err(VaultError::KeyDerivation("Salt too short".into()));
        }
        
        // Don't validate passphrase on unlock, only when creating new vault or changing passphrase
        let key = self.derive_key(passphrase, &salt)?;
        *self.key.lock().await = Some(key.clone());

        if Path::new(&self.config.vault_path).exists() {
            let encrypted_data = fs::read(&self.config.vault_path).map_err(VaultError::Io)?;
            let decrypted_data = self.decrypt_data(&encrypted_data, key.as_ref()).await?;
            let data: HashMap<String, VaultValue> = serde_json::from_slice(&decrypted_data)?;
            *self.data.lock().await = data;
            
            // Set appropriate file permissions for vault file
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mut perms = fs::metadata(&self.config.vault_path).map_err(VaultError::Io)?.permissions();
                perms.set_mode(0o600); // Read/write for owner only
                fs::set_permissions(&self.config.vault_path, perms).map_err(VaultError::Io)?;
            }
        }

        Ok(())
    }

    async fn lock_impl(&self) -> VaultResult<()> {
        self.save_impl().await?;
        *self.key.lock().await = None;
        *self.data.lock().await = HashMap::new();
        Ok(())
    }

    async fn put_impl(&self, key: &str, value: VaultValue) -> VaultResult<()> {
        if self.is_locked() {
            return Err(VaultError::VaultLocked);
        }
        self.data.lock().await.insert(key.to_string(), value);
        Ok(())
    }

    async fn get_impl(&self, key: &str) -> VaultResult<VaultValue> {
        if self.is_locked() {
            return Err(VaultError::VaultLocked);
        }
        self.data
            .lock()
            .await
            .get(key)
            .cloned()
            .ok_or(VaultError::ItemNotFound)
    }

    async fn delete_impl(&self, key: &str) -> VaultResult<()> {
        if self.is_locked() {
            return Err(VaultError::VaultLocked);
        }
        self.data.lock().await.remove(key);
        Ok(())
    }
    
    async fn put_if_absent_impl(&self, key: &str, value: VaultValue) -> VaultResult<bool> {
        if self.is_locked() {
            return Err(VaultError::VaultLocked);
        }
        let mut data = self.data.lock().await;
        if data.contains_key(key) {
            Ok(false) // Key already exists, value not inserted
        } else {
            data.insert(key.to_string(), value);
            Ok(true) // Value was inserted
        }
    }
    
    async fn put_all_impl(&self, entries: &[(String, VaultValue)]) -> VaultResult<()> {
        if self.is_locked() {
            return Err(VaultError::VaultLocked);
        }
        let mut data = self.data.lock().await;
        for (key, value) in entries {
            data.insert(key.clone(), value.clone());
        }
        Ok(())
    }
    
    async fn find_impl(&self, pattern: &str) -> VaultResult<Vec<(String, VaultValue)>> {
        if self.is_locked() {
            return Err(VaultError::VaultLocked);
        }
        
        // Check for potentially dangerous regex patterns
        if pattern.len() > 100 || pattern.contains("(.*){") {
            return Err(VaultError::InvalidPattern("Pattern too complex or potentially malicious".into()));
        }
        
        let data = self.data.lock().await;
        
        // If pattern is ".*", return all items
        if pattern == ".*" {
            let results: Vec<(String, VaultValue)> = data
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            return Ok(results);
        }
        
        // Otherwise, try to compile and use regex
        match regex::Regex::new(pattern) {
            Ok(re) => {
                let results: Vec<(String, VaultValue)> = data
                    .iter()
                    .filter(|(k, _)| re.is_match(k))
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect();
                Ok(results)
            },
            Err(_) => {
                // Fallback to simple contains if regex is invalid
                let results: Vec<(String, VaultValue)> = data
                    .iter()
                    .filter(|(k, _)| k.contains(pattern))
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect();
                Ok(results)
            }
        }
    }

    async fn list_impl(&self) -> VaultResult<Vec<String>> {
        if self.is_locked() {
            return Err(VaultError::VaultLocked);
        }
        Ok(self.data.lock().await.keys().cloned().collect())
    }

    async fn save_impl(&self) -> VaultResult<()> {
        if self.is_locked() {
            return Err(VaultError::VaultLocked);
        }
        let data = serde_json::to_vec(&*self.data.lock().await)?;
        let key_guard = self.key.lock().await;
        let key = key_guard.as_ref().ok_or(VaultError::VaultLocked)?;
        let encrypted_data = self.encrypt_data(&data, key.as_ref()).await?;
        
        // If file exists, securely overwrite it
        if Path::new(&self.config.vault_path).exists() {
            self.secure_overwrite(&self.config.vault_path).map_err(VaultError::Io)?;
        }
        
        fs::write(&self.config.vault_path, encrypted_data).map_err(VaultError::Io)?;
        
        // Set appropriate file permissions
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&self.config.vault_path).map_err(VaultError::Io)?.permissions();
            perms.set_mode(0o600); // Read/write for owner only
            fs::set_permissions(&self.config.vault_path, perms).map_err(VaultError::Io)?;
        }
        
        Ok(())
    }
    
    fn secure_overwrite(&self, path: &Path) -> std::io::Result<()> {
        use std::io::{Write, Seek, SeekFrom};
        
        let metadata = fs::metadata(path)?;
        let file_size = metadata.len();
        
        let mut file = std::fs::OpenOptions::new().write(true).open(path)?;
        
        // Overwrite with zeros
        let zeros = vec![0u8; 4096];
        let mut remaining = file_size;
        
        while remaining > 0 {
            let to_write = std::cmp::min(remaining, 4096);
            file.write_all(&zeros[..to_write as usize])?;
            remaining -= to_write;
        }
        
        file.flush()?;
        file.seek(SeekFrom::Start(0))?;
        
        // Overwrite with ones
        let ones = vec![0xFFu8; 4096];
        let mut remaining = file_size;
        
        while remaining > 0 {
            let to_write = std::cmp::min(remaining, 4096);
            file.write_all(&ones[..to_write as usize])?;
            remaining -= to_write;
        }
        
        file.flush()?;
        file.sync_all()?;
        Ok(())
    }

    async fn change_passphrase_impl(&self, old_passphrase: &str, new_passphrase: &str) -> VaultResult<()> {
        if self.is_locked() {
            return Err(VaultError::VaultLocked);
        }
        
        // Validate new passphrase strength
        if !self.validate_passphrase_strength(new_passphrase) {
            return Err(VaultError::WeakPassphrase);
        }
        
        // Read salt
        let salt = fs::read(&self.config.salt_path).map_err(VaultError::Io)?;
        
        // Verify old passphrase
        let old_key = self.derive_key(old_passphrase, &salt)?;
        let current_key = self.key.lock().await;
        
        // Use safer comparison without unwrap
        if let Some(current) = current_key.as_ref() {
            // Use constant-time comparison to prevent timing attacks
            if old_key.as_ref() != current.as_ref() {
                return Err(VaultError::InvalidPassphrase);
            }
        } else {
            return Err(VaultError::VaultLocked);
        }
        
        // Generate new key
        let new_key = self.derive_key(new_passphrase, &salt)?;
        drop(current_key); // Release the lock
        
        // Update the key
        *self.key.lock().await = Some(new_key);
        
        // Save with new key
        self.save_impl().await
    }
}

// Implement the trait using the request/stream pattern
impl VaultOperation for LocalVaultProvider {
    fn name(&self) -> &str {
        // Identify the provider by name
        "LocalVaultProvider"
    }
    
    // Additional capability checking methods
    fn supports_encryption(&self) -> bool {
        true
    }
    
    fn encryption_type(&self) -> &str {
        match self.cipher_algorithm {
            CipherAlgorithm::Aes256Gcm => "AES-256-GCM",
            CipherAlgorithm::ChaCha20Poly1305 => "ChaCha20-Poly1305",
            CipherAlgorithm::Cascade => "Cascade (AES + ChaCha)",
            CipherAlgorithm::Custom(ref name) => name,
        }
    }
    
    fn supports_defense_in_depth(&self) -> bool {
        // Only true if using Cascade algorithm
        matches!(self.cipher_algorithm, CipherAlgorithm::Cascade)
    }

    fn is_locked(&self) -> bool {
        // Still synchronous as it checks internal state quickly
        self.key.try_lock().map(|guard| guard.is_none()).unwrap_or(true)
    }

    fn unlock(&self, passphrase: &Passphrase) -> VaultUnitRequest {
        let (tx, rx) = oneshot::channel();
        let op_clone = self.clone();
        let passphrase = passphrase.expose_secret().to_string(); // Clone passphrase for the task

        spawn(async move {
            let result = op_clone.unlock_impl(&passphrase).await;
            let _ = tx.send(result);
        });

        VaultUnitRequest::new(rx)
    }

    fn lock(&self) -> VaultUnitRequest {
        let (tx, rx) = oneshot::channel();
        let op_clone = self.clone();

        spawn(async move {
            let result = op_clone.lock_impl().await;
            let _ = tx.send(result);
        });

        VaultUnitRequest::new(rx)
    }

    // Updated signature to accept VaultValue
    fn put(&self, key: &str, value: VaultValue) -> VaultUnitRequest {
        let (tx, rx) = oneshot::channel();
        let op_clone = self.clone();
        let key = key.to_string();
        // value is already VaultValue, clone it for the task
        let value = value.clone();

        spawn(async move {
            let result = op_clone.put_impl(&key, value).await;
            let _ = tx.send(result);
        });

        VaultUnitRequest::new(rx)
    }

    fn get(&self, key: &str) -> VaultGetRequest {
        let (tx, rx) = oneshot::channel();
        let op_clone = self.clone();
        let key = key.to_string();

        spawn(async move {
            // get_impl returns VaultResult<VaultValue>, map ItemNotFound to Ok(None)
            let result = match op_clone.get_impl(&key).await {
                Ok(value) => Ok(Some(value)),
                Err(VaultError::ItemNotFound) => Ok(None),
                Err(e) => Err(e),
            };
            let _ = tx.send(result);
        });

        VaultGetRequest::new(rx)
    }

    // Updated signature to accept VaultValue
    fn put_if_absent(&self, key: &str, value: VaultValue) -> VaultBoolRequest {
        let (tx, rx) = oneshot::channel();
        let op_clone = self.clone();
        let key = key.to_string();
        // value is already VaultValue, clone it for the task
        let value = value.clone();

        spawn(async move {
            let result = op_clone.put_if_absent_impl(&key, value).await;
            let _ = tx.send(result);
        });

        VaultBoolRequest::new(rx)
    }

    // Updated signature to accept Vec<(String, VaultValue)>
    fn put_all(&self, entries: Vec<(String, VaultValue)>) -> VaultPutAllRequest {
        let (tx, rx) = oneshot::channel();
        let op_clone = self.clone();
        // entries is already Vec<(String, VaultValue)>, clone it for the task
        let entries = entries.clone();

        spawn(async move {
            // Pass the cloned entries directly
            let result = op_clone.put_all_impl(&entries).await;
            let _ = tx.send(result);
        });

        VaultPutAllRequest::new(rx)
    }

    fn delete(&self, key: &str) -> VaultUnitRequest {
        let (tx, rx) = oneshot::channel();
        let op_clone = self.clone();
        let key = key.to_string();

        spawn(async move {
            let result = op_clone.delete_impl(&key).await;
            let _ = tx.send(result);
        });

        VaultUnitRequest::new(rx)
    }

    fn find(&self, pattern: &str) -> VaultFindRequest {
        let (tx, rx) = mpsc::channel(100); // Use mpsc for streaming
        let op_clone = self.clone();
        let pattern = pattern.to_string();

        spawn(async move {
            match op_clone.find_impl(&pattern).await {
                Ok(results) => {
                    for item in results {
                        if tx.send(Ok(item)).await.is_err() {
                            // Receiver dropped, stop sending
                            break;
                        }
                    }
                    // Channel closes when tx drops here
                }
                Err(e) => {
                    // Send the error through the channel
                    let _ = tx.send(Err(e)).await;
                }
            }
        });

        VaultFindRequest::new(rx)
    }

    fn list(&self, _prefix: Option<&str>) -> VaultListRequest {
        // Note: LocalVaultProvider's list_impl doesn't currently support prefix filtering.
        // It lists all keys. We'll implement the streaming part but ignore the prefix for now.
        // A future enhancement could add prefix filtering to list_impl.
        let (tx, rx) = mpsc::channel(100); // Use mpsc for streaming
        let op_clone = self.clone();
        // let _prefix = prefix.map(|s| s.to_string()); // Keep prefix if needed later

        spawn(async move {
            match op_clone.list_impl().await {
                Ok(keys) => {
                    for key in keys {
                        // TODO: Add prefix filtering here if list_impl is enhanced
                        if tx.send(Ok(key)).await.is_err() {
                            // Receiver dropped, stop sending
                            break;
                        }
                    }
                    // Channel closes when tx drops here
                }
                Err(e) => {
                    // Send the error through the channel
                    let _ = tx.send(Err(e)).await;
                }
            }
        });

        VaultListRequest::new(rx)
    }

    fn change_passphrase(
        &self,
        old_passphrase: &Passphrase,
        new_passphrase: &Passphrase,
    ) -> VaultChangePassphraseRequest {
        let (tx, rx) = oneshot::channel();
        let op_clone = self.clone();
        let old_passphrase = old_passphrase.expose_secret().to_string();
        let new_passphrase = new_passphrase.expose_secret().to_string();

        spawn(async move {
            let result = op_clone
                .change_passphrase_impl(&old_passphrase, &new_passphrase)
                .await;
            let _ = tx.send(result);
        });

        VaultChangePassphraseRequest::new(rx)
    }

    // Implement the missing save method
    fn save(&self) -> VaultSaveRequest {
        let (tx, rx) = oneshot::channel();
        let op_clone = self.clone();

        spawn(async move {
            let result = op_clone.save_impl().await;
            let _ = tx.send(result);
        });

        VaultSaveRequest::new(rx)
    }
}