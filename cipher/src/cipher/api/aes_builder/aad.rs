//! AES Additional Authenticated Data (AAD) handling
//!
//! Contains utilities and helpers for working with AAD in AES-GCM operations.
//! The main AAD implementations are in encrypt.rs and decrypt.rs files.

// Note: The primary AAD implementations (AadBuilder traits) are located in:
// - encrypt.rs for AesWithKeyAndData 
// - decrypt.rs for AesWithKeyAndCiphertext
//
// This file is reserved for future AAD-specific utilities and helpers.
// Currently, no additional AAD-specific code was found in the original file
// beyond what was already extracted to encrypt.rs and decrypt.rs.

/// AAD serialization helper (placeholder for future AAD utilities)
pub(crate) fn _serialize_aad_helper(aad: &std::collections::HashMap<String, String>) -> Result<Vec<u8>, crate::CryptError> {
    if aad.is_empty() {
        Ok(Vec::new())
    } else {
        serde_json::to_vec(aad).map_err(|e| {
            crate::CryptError::SerializationError(format!("AAD serialization failed: {}", e))
        })
    }
}

/// AAD deserialization helper (placeholder for future AAD utilities)
pub(crate) fn _deserialize_aad_helper(aad_bytes: &[u8]) -> Result<std::collections::HashMap<String, String>, crate::CryptError> {
    if aad_bytes.is_empty() {
        Ok(std::collections::HashMap::new())
    } else {
        serde_json::from_slice(aad_bytes).map_err(|e| {
            crate::CryptError::DecryptionFailed(format!("AAD deserialization failed: {}", e))
        })
    }
}