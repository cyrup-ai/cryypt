//! Certificate key information extraction operations
//!
//! This module provides functionality for extracting key algorithm information,
//! key sizes, and cryptographic parameters from X.509 certificates.

use der::{AnyRef, Encode, Reader, SliceReader, Tag};
use x509_cert::Certificate as X509CertCert;

// Using available const_oid constants based on actual const_oid 0.9 API
use const_oid::db::rfc5912::{
    ID_EC_PUBLIC_KEY, SECP_224_R_1, SECP_256_R_1, SECP_384_R_1, SECP_521_R_1,
};
use const_oid::db::rfc8410::{ID_ED_448, ID_ED_25519, ID_X_448, ID_X_25519};

/// Extract key algorithm name and size from X.509 certificate
pub fn extract_key_info_from_cert(cert: &X509CertCert) -> (String, Option<u32>) {
    // Define common algorithm OIDs manually since some are not available in const_oid 0.9
    const RSA_ENCRYPTION_OID: &str = "1.2.840.113549.1.1.1";
    const DSA_OID: &str = "1.2.840.10040.4.1";
    const DH_OID: &str = "1.2.840.10046.2.1";

    let algorithm = &cert.tbs_certificate.subject_public_key_info.algorithm;
    let algorithm_oid = &algorithm.oid;

    let algorithm_oid_str = algorithm_oid.to_string();
    let algorithm_name = if algorithm_oid_str == RSA_ENCRYPTION_OID {
        "RSA".to_string()
    } else if algorithm_oid_str == DSA_OID {
        "DSA".to_string()
    } else if algorithm_oid_str == DH_OID {
        "DH".to_string()
    } else if *algorithm_oid == ID_EC_PUBLIC_KEY {
        "ECDSA".to_string()
    } else if *algorithm_oid == ID_X_25519 {
        "X25519".to_string()
    } else if *algorithm_oid == ID_X_448 {
        "X448".to_string()
    } else if *algorithm_oid == ID_ED_25519 {
        "Ed25519".to_string()
    } else if *algorithm_oid == ID_ED_448 {
        "Ed448".to_string()
    } else {
        "Unknown".to_string()
    };

    // Extract actual key size from certificate using production cryptographic parsing
    let key_size = if let Some(public_key_bits) = cert
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .as_bytes()
    {
        // Create a proper BitStringRef from the raw bytes
        match der::asn1::BitStringRef::new(0, public_key_bits) {
            Ok(public_key_ref) => {
                extract_key_size_from_algorithm_and_key(algorithm, &public_key_ref)
            }
            Err(e) => {
                tracing::warn!("Failed to create BitStringRef: {}", e);
                None
            }
        }
    } else {
        tracing::warn!("Failed to get public key bytes from certificate");
        None
    };

    (algorithm_name, key_size)
}

/// Extract key size from algorithm and public key data
pub(super) fn extract_key_size_from_algorithm_and_key(
    algorithm: &spki::AlgorithmIdentifier<der::Any>,
    public_key: &der::asn1::BitStringRef,
) -> Option<u32> {
    // Define common algorithm OIDs locally
    const RSA_ENCRYPTION_OID: &str = "1.2.840.113549.1.1.1";
    const DSA_OID: &str = "1.2.840.10040.4.1";
    const DH_OID: &str = "1.2.840.10046.2.1";

    let oid_str = algorithm.oid.to_string();
    if oid_str == RSA_ENCRYPTION_OID {
        extract_rsa_key_size(public_key)
    } else if oid_str == DSA_OID || oid_str == DH_OID {
        extract_dh_like_key_size(algorithm.parameters.as_ref().map(AnyRef::from))
    } else if algorithm.oid == ID_EC_PUBLIC_KEY {
        extract_ec_key_size(algorithm.parameters.as_ref().map(AnyRef::from))
    } else if algorithm.oid == ID_X_25519 {
        Some(256)
    } else if algorithm.oid == ID_X_448 {
        Some(448)
    } else if algorithm.oid == ID_ED_25519 {
        Some(256)
    } else if algorithm.oid == ID_ED_448 {
        Some(448)
    } else {
        None
    }
}

/// Compute the bit length of a big-endian byte slice representing a positive integer
fn compute_bit_length(bytes: &[u8]) -> Option<u32> {
    let start = bytes.iter().position(|&b| b != 0)?;
    let effective = &bytes[start..];
    if effective.is_empty() {
        return None;
    }
    let high_byte = effective[0];
    let high_bits = 8u32 - high_byte.leading_zeros();
    #[allow(clippy::cast_possible_truncation)]
    let rest_bits = ((effective.len() - 1) * 8) as u32;
    Some(high_bits + rest_bits)
}

/// Skip a single ASN.1 element using a `SliceReader`
fn skip_element(reader: &mut der::SliceReader) -> Option<()> {
    let header = reader.peek_header().ok()?;
    let header_len: usize = header.encoded_len().ok()?.try_into().ok()?;
    let content_len: usize = header.length.try_into().ok()?;
    let total_len = header_len + content_len;
    reader
        .read_slice(der::Length::try_from(total_len).ok()?)
        .ok()?;
    Some(())
}

/// Extract RSA modulus size in bits from RSA public key
fn extract_rsa_key_size(public_key: &der::asn1::BitStringRef) -> Option<u32> {
    let key_bytes = public_key.as_bytes()?;
    let mut reader = der::SliceReader::new(key_bytes).ok()?;

    let sequence_header = reader.peek_header().ok()?;
    if sequence_header.tag != Tag::Sequence {
        return None;
    }
    // Skip the sequence header to get to the content
    let header_len = sequence_header.encoded_len().ok()?;
    reader.read_slice(header_len).ok()?;

    let modulus_header = reader.peek_header().ok()?;
    if modulus_header.tag != Tag::Integer {
        return None;
    }
    // Skip the integer header to get to the modulus content
    let modulus_header_len = modulus_header.encoded_len().ok()?;
    reader.read_slice(modulus_header_len).ok()?;

    let modulus_bytes = reader.read_slice(modulus_header.length).ok()?;
    compute_bit_length(modulus_bytes)
}

/// Extract key size for DH-like algorithms (DSA, DH) from parameters
fn extract_dh_like_key_size(parameters_opt: Option<AnyRef>) -> Option<u32> {
    let parameters = parameters_opt?;
    let bytes = parameters.value();
    let mut reader = der::SliceReader::new(bytes).ok()?;

    let sequence_header = reader.peek_header().ok()?;
    if sequence_header.tag != der::Tag::Sequence {
        return None;
    }
    let seq_header_len = sequence_header.encoded_len().ok()?;
    reader.read_slice(seq_header_len).ok()?;

    let p_header = reader.peek_header().ok()?;
    if p_header.tag != der::Tag::Integer {
        return None;
    }
    let p_header_len = p_header.encoded_len().ok()?;
    reader.read_slice(p_header_len).ok()?;

    let p_bytes = reader.read_slice(p_header.length).ok()?;
    compute_bit_length(p_bytes)
}

/// Extract EC key size from curve parameters
fn extract_ec_key_size(parameters_opt: Option<AnyRef>) -> Option<u32> {
    let parameters = parameters_opt?;
    let bytes = parameters.value();
    let mut reader = SliceReader::new(bytes).ok()?;

    let header = reader.peek_header().ok()?;
    match header.tag {
        Tag::ObjectIdentifier => {
            let header_len = header.encoded_len().ok()?;
            reader.read_slice(header_len).ok()?;
            // Read the OID bytes and create ObjectIdentifier
            let oid_bytes = reader.read_slice(header.length).ok()?;
            let curve_oid = const_oid::ObjectIdentifier::from_bytes(oid_bytes).ok()?;
            match curve_oid {
                SECP_224_R_1 => Some(224),
                SECP_256_R_1 => Some(256),
                SECP_384_R_1 => Some(384),
                SECP_521_R_1 => Some(521),
                _ => {
                    // Handle other curves by OID string matching
                    let oid_str = curve_oid.to_string();
                    match oid_str.as_str() {
                        // SECP192R1 and SECP192K1 both have 192-bit keys
                        "1.2.840.10045.3.1.1" | "1.3.132.0.31" => Some(192),
                        "1.3.132.0.32" => Some(224), // SECP224K1
                        "1.3.132.0.10" => Some(256), // SECP256K1
                        _ => None,
                    }
                }
            }
        }
        Tag::Sequence => {
            // specifiedCurve: ECParameters
            let header_len = header.encoded_len().ok()?;
            reader.read_slice(header_len).ok()?;
            // Skip version INTEGER
            skip_element(&mut reader)?;
            // Skip fieldID SEQUENCE
            skip_element(&mut reader)?;
            // Skip curve SEQUENCE
            skip_element(&mut reader)?;
            // Skip base OCTET STRING
            skip_element(&mut reader)?;
            // Now order INTEGER
            let order_header = reader.peek_header().ok()?;
            if order_header.tag != Tag::Integer {
                return None;
            }
            let order_header_len = order_header.encoded_len().ok()?;
            reader.read_slice(order_header_len).ok()?;
            let order_bytes = reader.read_slice(order_header.length).ok()?;
            compute_bit_length(order_bytes)
        }
        _ => None,
    }
}
