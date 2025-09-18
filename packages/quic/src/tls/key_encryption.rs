//! Private key encryption and decryption utilities

use std::collections::HashSet;
use std::env;

use super::errors::TlsError;
use super::types::{PBKDF2_ITERATIONS, SecureKeyMaterial};

/// Validate encryption passphrase from deployment environment
fn validate_encryption_passphrase() -> Result<String, TlsError> {
    // Get encryption passphrase from environment variable
    let passphrase = env::var("CRYYPT_KEY_ENCRYPTION_PASSPHRASE").map_err(|_| {
        TlsError::KeyProtection(
            "CRYYPT_KEY_ENCRYPTION_PASSPHRASE environment variable not set".to_string(),
        )
    })?;

    // Validate passphrase strength - minimum 32 characters
    if passphrase.len() < 32 {
        return Err(TlsError::KeyProtection(
            "Encryption passphrase must be at least 32 characters".to_string(),
        ));
    }

    // Enhanced entropy validation - character class requirements
    let has_lowercase = passphrase.chars().any(char::is_lowercase);
    let has_uppercase = passphrase.chars().any(char::is_uppercase);
    let has_digit = passphrase.chars().any(|c| c.is_ascii_digit());
    let has_symbol = passphrase.chars().any(|c| !c.is_alphanumeric());

    let char_classes = [has_lowercase, has_uppercase, has_digit, has_symbol]
        .iter()
        .filter(|&&x| x)
        .count();

    if char_classes < 3 {
        return Err(TlsError::KeyProtection(
            "Encryption passphrase must contain at least 3 character classes (lowercase, uppercase, digits, symbols)".to_string()
        ));
    }

    // Validate entropy - check for repeated characters
    let unique_chars: HashSet<char> = passphrase.chars().collect();
    if unique_chars.len() < 12 {
        return Err(TlsError::KeyProtection(
            "Encryption passphrase must contain at least 12 unique characters".to_string(),
        ));
    }

    // Check for common patterns (sequential characters, repeated sequences)
    if has_weak_patterns(&passphrase) {
        return Err(TlsError::KeyProtection(
            "Encryption passphrase contains weak patterns (sequential or repeated characters)"
                .to_string(),
        ));
    }

    Ok(passphrase)
}

/// Check for weak patterns in passphrase
#[must_use]
fn has_weak_patterns(passphrase: &str) -> bool {
    let chars: Vec<char> = passphrase.chars().collect();

    // Check for sequential characters (e.g., "abc", "123")
    for window in chars.windows(3) {
        if window.len() == 3 {
            let a = window[0] as u32;
            let b = window[1] as u32;
            let c = window[2] as u32;

            // Ascending or descending sequence
            if (b == a + 1 && c == b + 1) || (b == a - 1 && c == b - 1) {
                return true;
            }
        }
    }

    // Check for repeated substrings of length 3 or more
    for i in 0..chars.len().saturating_sub(5) {
        for len in 3..=((chars.len() - i) / 2) {
            if i + len * 2 <= chars.len() {
                let first = &chars[i..i + len];
                let second = &chars[i + len..i + len * 2];
                if first == second {
                    return true;
                }
            }
        }
    }

    false
}

/// Encrypt private key data using AES-256-GCM authenticated encryption
pub fn encrypt_private_key(key_pem: &str) -> Result<Vec<u8>, TlsError> {
    use ring::{aead, pbkdf2, rand};

    // Get and validate passphrase from environment
    let passphrase = validate_encryption_passphrase()?;

    // Generate random salt for PBKDF2
    let rng = rand::SystemRandom::new();
    let mut salt = [0u8; 32];
    rand::SecureRandom::fill(&rng, &mut salt)
        .map_err(|_| TlsError::KeyProtection("Failed to generate random salt".to_string()))?;

    // Derive key using PBKDF2
    let mut key_bytes = [0u8; 32];
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        PBKDF2_ITERATIONS,
        &salt,
        passphrase.as_bytes(),
        &mut key_bytes,
    );

    // Create AES-256-GCM key
    let key = aead::UnboundKey::new(&aead::AES_256_GCM, &key_bytes)
        .map_err(|_| TlsError::KeyProtection("Failed to create encryption key".to_string()))?;
    let key = aead::LessSafeKey::new(key);

    // Generate random nonce
    let mut nonce_bytes = [0u8; 12];
    rand::SecureRandom::fill(&rng, &mut nonce_bytes)
        .map_err(|_| TlsError::KeyProtection("Failed to generate random nonce".to_string()))?;
    let nonce = aead::Nonce::assume_unique_for_key(nonce_bytes);

    // Encrypt the key data
    let mut plaintext = key_pem.as_bytes().to_vec();
    key.seal_in_place_append_tag(nonce, aead::Aad::empty(), &mut plaintext)
        .map_err(|_| TlsError::KeyProtection("Encryption failed".to_string()))?;

    // Format: [salt:32][nonce:12][ciphertext+tag]
    let mut result = Vec::with_capacity(32 + 12 + plaintext.len());
    result.extend_from_slice(&salt);
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&plaintext);

    Ok(result)
}

/// Decrypt private key data using AES-256-GCM authenticated encryption
pub fn decrypt_private_key(encrypted_data: &[u8]) -> Result<SecureKeyMaterial, TlsError> {
    use ring::{aead, pbkdf2};

    // Validate minimum size: salt(32) + nonce(12) + tag(16) = 60 bytes minimum
    if encrypted_data.len() < 60 {
        return Err(TlsError::KeyProtection(
            "Invalid encrypted data format".to_string(),
        ));
    }

    // Extract components
    let salt = &encrypted_data[0..32];
    let nonce_bytes = &encrypted_data[32..44];
    let ciphertext = &encrypted_data[44..];

    // Get and validate passphrase from environment
    let passphrase = validate_encryption_passphrase()?;

    // Derive key using same parameters
    let mut key_bytes = [0u8; 32];
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        PBKDF2_ITERATIONS,
        salt,
        passphrase.as_bytes(),
        &mut key_bytes,
    );

    // Create AES-256-GCM key
    let key = aead::UnboundKey::new(&aead::AES_256_GCM, &key_bytes)
        .map_err(|_| TlsError::KeyProtection("Failed to create decryption key".to_string()))?;
    let key = aead::LessSafeKey::new(key);

    // Create nonce
    let mut nonce_array = [0u8; 12];
    nonce_array.copy_from_slice(nonce_bytes);
    let nonce = aead::Nonce::assume_unique_for_key(nonce_array);

    // Decrypt and authenticate - use constant error message to prevent timing attacks
    let mut ciphertext_copy = ciphertext.to_vec();
    let decrypted = key
        .open_in_place(nonce, aead::Aad::empty(), &mut ciphertext_copy)
        .map_err(|_| TlsError::KeyProtection("Authentication failed".to_string()))?;

    Ok(SecureKeyMaterial::new(decrypted.to_vec()))
}
