//! Simplified decryption builder for raw bytes

use super::{AsyncDecryptionResult, HasData};
use crate::{cipher::encryption_result::DecryptionResultImpl, CryptError};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use chacha20poly1305::ChaCha20Poly1305;

/// Decryption builder
pub struct DecryptionBuilder<C, D> {
    pub(super) _cipher: C,
    pub(super) data: D,
}

impl DecryptionBuilder<(), HasData<Vec<u8>>> {
    /// Decrypt with AES-GCM using provided key - Direct async implementation
    pub fn with_aes_key(self, key: &[u8]) -> impl AsyncDecryptionResult {
        let encrypted = self.data.0;
        let key = key.to_vec();
        let (tx, rx) = tokio::sync::oneshot::channel();

        tokio::spawn(async move {
            // Direct async execution using fast AES-GCM operations suitable for async context
            let result = decrypt_aes_gcm(&encrypted, &key);
            let _ = tx.send(result);
        });

        DecryptionResultImpl::new(rx)
    }

    /// Decrypt with ChaCha20-Poly1305 using provided key
    pub fn with_chacha_key(self, key: &[u8]) -> impl AsyncDecryptionResult {
        let encrypted = self.data.0;
        let key = key.to_vec();
        let (tx, rx) = tokio::sync::oneshot::channel();

        tokio::spawn(async move {
            // Direct async execution using fast ChaCha20-Poly1305 operations suitable for async context
            let result = decrypt_chacha20_poly1305(&encrypted, &key);
            let _ = tx.send(result);
        });

        DecryptionResultImpl::new(rx)
    }
}

// Helper functions
fn decrypt_aes_gcm(encrypted: &[u8], key: &[u8]) -> crate::Result<Vec<u8>> {
    if encrypted.len() < 12 {
        return Err(CryptError::DecryptionFailed(
            "Invalid ciphertext length".into(),
        ));
    }

    let (nonce_bytes, ciphertext_with_tag) = encrypted.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);

    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| CryptError::InvalidKey(format!("Invalid AES key: {e}")))?;

    cipher
        .decrypt(nonce, ciphertext_with_tag)
        .map_err(|e| CryptError::DecryptionFailed(format!("AES decryption failed: {e}")))
}

fn decrypt_chacha20_poly1305(encrypted: &[u8], key: &[u8]) -> crate::Result<Vec<u8>> {
    if encrypted.len() < 12 {
        return Err(CryptError::DecryptionFailed(
            "Invalid ciphertext length".into(),
        ));
    }

    let (nonce_bytes, ciphertext_with_tag) = encrypted.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);

    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| CryptError::InvalidKey(format!("Invalid ChaCha20 key: {e}")))?;

    cipher
        .decrypt(nonce, ciphertext_with_tag)
        .map_err(|e| CryptError::DecryptionFailed(format!("ChaCha20 decryption failed: {e}")))
}
