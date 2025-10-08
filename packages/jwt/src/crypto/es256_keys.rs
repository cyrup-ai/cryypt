//! ES256 key generation for ECDSA P-256

use crate::{
    error::{JwtError, JwtResult},
    types::Es256KeyPair,
};
/// Generate ES256 key pair - Production async implementation
#[allow(dead_code)]
pub fn es256_generate_keys() -> JwtResult<Es256KeyPair> {
    // Direct async implementation - key generation is fast enough for direct execution
    // Use the algorithms module to generate keys
    let keypair = crate::algorithms::generate_es256_keypair()?;

    // Validate the generated keypair
    if crate::algorithms::validate_es256_keypair(&keypair) {
        Ok(keypair)
    } else {
        Err(JwtError::invalid_key(
            "Failed to generate valid ES256 keypair",
        ))
    }
}
