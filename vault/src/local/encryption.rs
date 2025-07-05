use argon2::{Argon2, password_hash::SaltString};
use zeroize::Zeroizing;

use super::vault::LocalVaultProvider;
use crate::error::{VaultError, VaultResult};
use cryypt_cipher::CipherAlgorithm;

impl LocalVaultProvider {
    // Internal async implementation of operations
    pub(crate) fn validate_passphrase_strength(&self, passphrase: &str) -> bool {
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
    pub(crate) fn derive_key(&self, passphrase: &str, salt: &[u8]) -> VaultResult<Zeroizing<Vec<u8>>> {
        // Determine key size based on cipher algorithm
        let key_size = match self.cipher_algorithm {
            CipherAlgorithm::Cascade => 64, // 2x 32-byte keys
            _ => 32,                        // Single 32-byte key
        };

        let argon2 = Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            argon2::Params::new(
                self.config.argon2_memory_cost,
                self.config.argon2_time_cost,
                self.config.argon2_parallelism,
                Some(key_size),
            )
            .map_err(|e| VaultError::KeyDerivation(e.to_string()))?,
        );

        let salt_string =
            SaltString::encode_b64(salt).map_err(|e| VaultError::KeyDerivation(e.to_string()))?;

        let mut output = vec![0u8; key_size];
        argon2
            .hash_password_into(
                passphrase.as_bytes(),
                salt_string.as_salt().as_str().as_bytes(),
                &mut output,
            )
            .map_err(|e| VaultError::KeyDerivation(e.to_string()))?;

        Ok(Zeroizing::new(output))
    }

    /// Encrypt data using the cipher API
    pub(crate) async fn encrypt_data(&self, data: &[u8], key: &[u8]) -> VaultResult<Vec<u8>> {
        use cryypt_cipher::{Cipher, prelude::*};
        use cryypt_key::{KeyResult, traits::KeyProviderBuilder};

        // Create a raw key provider that returns the key directly
        struct RawKeyProvider {
            key: Vec<u8>,
        }

        impl KeyProviderBuilder for RawKeyProvider {
            fn resolve(&self) -> KeyResult {
                KeyResult::ready(Ok(self.key.clone()))
            }
        }

        let key_provider = RawKeyProvider { key: key.to_vec() };

        // Use the configured cipher algorithm
        match self.cipher_algorithm {
            CipherAlgorithm::Aes256Gcm => Cipher::aes()
                .with_key(key_provider)
                .with_data(data)
                .encrypt()
                .await
                .map(|result| result.to_bytes())
                .map_err(|e| VaultError::Encryption(e.to_string())),
            CipherAlgorithm::ChaCha20Poly1305 => Cipher::chachapoly()
                .with_key(key_provider)
                .with_data(data)
                .encrypt()
                .await
                .map(|result| result.to_bytes())
                .map_err(|e| VaultError::Encryption(e.to_string())),
            CipherAlgorithm::Cascade => {
                // For cascade, we need to split the key for two passes
                if key.len() < 64 {
                    return Err(VaultError::Encryption(
                        "Cascade requires 64-byte key".into(),
                    ));
                }

                let (aes_key, chacha_key) = key.split_at(32);

                // First pass with AES
                let aes_provider = RawKeyProvider {
                    key: aes_key.to_vec(),
                };

                // Second pass with ChaCha
                let chacha_provider = RawKeyProvider {
                    key: chacha_key.to_vec(),
                };

                // Use the two-pass encryption
                Cipher::aes()
                    .with_key(aes_provider)
                    .with_data(data)
                    .second_pass(Cipher::chachapoly().with_key(chacha_provider))
                    .encrypt()
                    .await
                    .map(|result| result.to_bytes())
                    .map_err(|e| VaultError::Encryption(e.to_string()))
            }
            CipherAlgorithm::Custom(ref name) => Err(VaultError::Encryption(format!(
                "Custom cipher '{}' not implemented",
                name
            ))),
        }
    }

    /// Decrypt data using the cipher API
    pub(crate) async fn decrypt_data(&self, encrypted_data: &[u8], key: &[u8]) -> VaultResult<Vec<u8>> {
        use cryypt_cipher::{Cipher, prelude::*};
        use cryypt_key::{KeyResult, traits::KeyProviderBuilder};

        // Create a raw key provider that returns the key directly
        struct RawKeyProvider {
            key: Vec<u8>,
        }

        impl KeyProviderBuilder for RawKeyProvider {
            fn resolve(&self) -> KeyResult {
                KeyResult::ready(Ok(self.key.clone()))
            }
        }

        // Use the configured cipher algorithm
        match self.cipher_algorithm {
            CipherAlgorithm::Aes256Gcm => {
                // The cipher API handles the encrypted data format internally
                Cipher::decrypt(encrypted_data.to_vec())
                    .with_aes_key(key)
                    .await
                    .map_err(|e| VaultError::Decryption(e.to_string()))
            }
            CipherAlgorithm::ChaCha20Poly1305 => Cipher::decrypt(encrypted_data.to_vec())
                .with_chacha_key(key)
                .await
                .map_err(|e| VaultError::Decryption(e.to_string())),
            CipherAlgorithm::Cascade => {
                // For cascade, we need to split the key for two passes
                if key.len() < 64 {
                    return Err(VaultError::Decryption(
                        "Cascade requires 64-byte key".into(),
                    ));
                }

                let (aes_key, chacha_key) = key.split_at(32);

                // The cascade decryption is done in reverse order: ChaCha first, then AES
                let intermediate = Cipher::decrypt(encrypted_data.to_vec())
                    .with_chacha_key(chacha_key)
                    .await
                    .map_err(|e| VaultError::Decryption(e.to_string()))?;

                Cipher::decrypt(intermediate)
                    .with_aes_key(aes_key)
                    .await
                    .map_err(|e| VaultError::Decryption(e.to_string()))
            }
            CipherAlgorithm::Custom(ref name) => Err(VaultError::Decryption(format!(
                "Custom cipher '{}' not implemented",
                name
            ))),
        }
    }
}