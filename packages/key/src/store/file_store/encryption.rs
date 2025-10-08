//! Encryption Operations for File-based Key Storage
//!
//! This module provides AES-GCM encryption and decryption operations for protecting
//! key material stored in files using a master key.

use crate::{KeyError, Result};
use aes_gcm::{
    Aes256Gcm,
    aead::{Aead, KeyInit, generic_array::GenericArray},
};
use zeroize::Zeroizing;

/// Encrypt key material using AES-GCM with the provided master key
pub(super) fn encrypt_key_material(key_material: &[u8], master_key: &[u8; 32]) -> Result<Vec<u8>> {
    use rand::RngCore;

    // Generate random nonce
    let mut nonce = vec![0u8; 12];
    rand::rng().fill_bytes(&mut nonce);
    let nonce_array = GenericArray::from_slice(&nonce);

    // Create cipher with master key
    let cipher = Aes256Gcm::new_from_slice(master_key.as_ref())
        .map_err(|e| KeyError::InvalidKey(format!("Invalid master key: {e}")))?;

    // Encrypt key material
    let ciphertext = cipher
        .encrypt(nonce_array, key_material)
        .map_err(|_| KeyError::EncryptionFailed("Key encryption failed".into()))?;

    // Combine nonce + ciphertext
    let mut encrypted_data = nonce;
    encrypted_data.extend_from_slice(&ciphertext);

    Ok(encrypted_data)
}

/// Decrypt key material using AES-GCM with the provided master key
pub(super) fn decrypt_key_material(
    encrypted_data: &[u8],
    master_key: &[u8; 32],
) -> Result<Vec<u8>> {
    // Validate minimum size (12 bytes nonce + at least 16 bytes ciphertext)
    if encrypted_data.len() < 28 {
        return Err(KeyError::DecryptionFailed(
            "Invalid encrypted key format".into(),
        ));
    }

    // Extract nonce and ciphertext
    let nonce = &encrypted_data[..12];
    let ciphertext = &encrypted_data[12..];
    let nonce_array = GenericArray::from_slice(nonce);

    // Create cipher with master key
    let cipher = Aes256Gcm::new_from_slice(master_key.as_ref())
        .map_err(|e| KeyError::InvalidKey(format!("Invalid master key: {e}")))?;

    // Decrypt key material
    let decrypted = cipher
        .decrypt(nonce_array, ciphertext)
        .map_err(|_| KeyError::DecryptionFailed("Key decryption failed".into()))?;

    Ok(decrypted)
}

/// Generate cryptographically secure key material of the specified size
#[allow(dead_code)] // Utility function for future use
pub(super) fn generate_key_material(size_bytes: usize) -> (Vec<u8>, Vec<u8>) {
    use rand::RngCore;

    // Generate random key material
    let mut key_material = Zeroizing::new(vec![0u8; size_bytes]);
    rand::rng().fill_bytes(&mut key_material);

    // Generate random nonce
    let mut nonce = vec![0u8; 12];
    rand::rng().fill_bytes(&mut nonce);

    (key_material.to_vec(), nonce)
}
