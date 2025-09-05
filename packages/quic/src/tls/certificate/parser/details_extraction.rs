//! Certificate details extraction operations
//!
//! This module provides functionality for extracting detailed certificate information
//! including Subject Alternative Names, BasicConstraints, KeyUsage, and validity periods.

use std::time::SystemTime;
use der::{Decode, Reader, SliceReader, Tag, TagNumber};
use x509_cert::Certificate as X509CertCert;

use crate::tls::errors::TlsError;

/// Extract certificate details using x509-cert
pub fn extract_certificate_details(
    cert: &X509CertCert,
) -> Result<
    (
        Vec<String>,
        Vec<std::net::IpAddr>,
        bool,
        Vec<String>,
        SystemTime,
        SystemTime,
    ),
    TlsError,
> {
    // Extract SANs
    let mut san_dns_names = Vec::new();
    let mut san_ip_addresses = Vec::new();

    // Extract BasicConstraints for CA flag
    let mut is_ca = false;

    // Extract key usage
    let mut key_usage = Vec::new();

    // OIDs for extensions
    const OID_SUBJECT_ALT_NAME: &str = "2.5.29.17";
    const OID_BASIC_CONSTRAINTS: &str = "2.5.29.19";
    const OID_KEY_USAGE: &str = "2.5.29.15";

    // Process extensions
    if let Some(extensions) = &cert.tbs_certificate.extensions {
        for ext in extensions.iter() {
            let oid_string = ext.extn_id.to_string();

            match oid_string.as_str() {
                OID_SUBJECT_ALT_NAME => {
                    // Parse SubjectAltName extension properly using ASN.1
                    // SubjectAltName ::= GeneralNames
                    // GeneralNames ::= SEQUENCE OF GeneralName

                    let ext_data = ext.extn_value.as_bytes();

                    // Parse the OCTET STRING wrapper first
                    match der::asn1::OctetString::from_der(ext_data) {
                        Ok(octet_string) => {
                            // Now parse the actual SubjectAltName SEQUENCE
                            let san_data = octet_string.as_bytes();
                            let mut reader = match SliceReader::new(san_data) {
                                Ok(reader) => reader,
                                Err(_) => {
                                    tracing::warn!("Failed to create DER reader for SAN data");
                                    continue;
                                }
                            };

                            // Read the SEQUENCE header
                            if let Ok(header) = reader.peek_header() {
                                if header.tag == Tag::Sequence {
                                    // Consume the header
                                    match reader.peek_header() {
                                        Ok(_) => {}
                                        Err(_) => {
                                            tracing::warn!("Failed to consume sequence header");
                                            continue;
                                        }
                                    }
                                    match reader.read_slice(header.length) {
                                        Ok(_) => {}
                                        Err(_) => {
                                            tracing::warn!("Failed to read sequence data");
                                            continue;
                                        }
                                    }

                                    // Parse each GeneralName in the sequence
                                    while !reader.is_finished() {
                                        if let Ok(name_header) = reader.peek_header() {
                                            match name_header.tag.number() {
                                                TagNumber::N2 => {
                                                    // dNSName [2] IMPLICIT IA5String
                                                    if let Ok(dns_header) = reader.peek_header() {
                                                        if let Ok(dns_bytes) =
                                                            reader.read_vec(dns_header.length)
                                                        {
                                                            if let Ok(dns_name) =
                                                                std::str::from_utf8(&dns_bytes)
                                                            {
                                                                san_dns_names
                                                                    .push(dns_name.to_string());
                                                            }
                                                        }
                                                    }
                                                }
                                                TagNumber::N7 => {
                                                    // iPAddress [7] IMPLICIT OCTET STRING
                                                    if let Ok(ip_header) = reader.peek_header() {
                                                        if let Ok(ip_bytes) =
                                                            reader.read_vec(ip_header.length)
                                                        {
                                                            // IPv4 = 4 bytes, IPv6 = 16 bytes
                                                            match ip_bytes.len() {
                                                                4 => {
                                                                    let octets: [u8; 4] =
                                                                        match ip_bytes.try_into() {
                                                                            Ok(octets) => octets,
                                                                            Err(_) => {
                                                                                tracing::warn!("Invalid IPv4 address bytes");
                                                                                continue;
                                                                            }
                                                                        };
                                                                    san_ip_addresses
                                                                        .push(std::net::IpAddr::V4(
                                                                        std::net::Ipv4Addr::from(
                                                                            octets,
                                                                        ),
                                                                    ));
                                                                }
                                                                16 => {
                                                                    let octets: [u8; 16] =
                                                                        match ip_bytes.try_into() {
                                                                            Ok(octets) => octets,
                                                                            Err(_) => {
                                                                                tracing::warn!("Invalid IPv6 address bytes");
                                                                                continue;
                                                                            }
                                                                        };
                                                                    san_ip_addresses
                                                                        .push(std::net::IpAddr::V6(
                                                                        std::net::Ipv6Addr::from(
                                                                            octets,
                                                                        ),
                                                                    ));
                                                                }
                                                                _ => {
                                                                    // Invalid IP address length
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                                _ => {
                                                    // Skip other GeneralName types
                                                    // (rfc822Name, x400Address, directoryName, ediPartyName, uniformResourceIdentifier, registeredID)
                                                    let _ = reader.peek_header();
                                                    let _ = reader.read_slice(name_header.length);
                                                }
                                            }
                                        } else {
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            tracing::error!("Failed to parse SubjectAltName extension: {}", e);
                        }
                    }
                }
                OID_BASIC_CONSTRAINTS => {
                    // Parse BasicConstraints extension
                    // Structure: SEQUENCE { cA BOOLEAN DEFAULT FALSE, ... }
                    let ext_data = ext.extn_value.as_bytes();

                    // Look for the CA boolean flag
                    // In DER encoding, BOOLEAN TRUE is 0x01 0x01 0xFF
                    if ext_data.len() >= 3 {
                        for i in 0..ext_data.len() - 2 {
                            if ext_data[i] == 0x01
                                && ext_data[i + 1] == 0x01
                                && ext_data[i + 2] == 0xFF
                            {
                                is_ca = true;
                                break;
                            }
                        }
                    }
                }
                OID_KEY_USAGE => {
                    // Parse KeyUsage extension
                    // Structure: BIT STRING with specific bit positions
                    let ext_data = ext.extn_value.as_bytes();

                    // KeyUsage bits (from RFC 5280):
                    // 0: digitalSignature
                    // 1: nonRepudiation/contentCommitment
                    // 2: keyEncipherment
                    // 3: dataEncipherment
                    // 4: keyAgreement
                    // 5: keyCertSign
                    // 6: cRLSign
                    // 7: encipherOnly
                    // 8: decipherOnly

                    // Find the bit string in the extension data
                    // BIT STRING starts with tag 0x03
                    for i in 0..ext_data.len() {
                        if ext_data[i] == 0x03 && i + 2 < ext_data.len() {
                            // Next byte is length, then unused bits, then the actual bits
                            if i + 3 < ext_data.len() {
                                let bits = ext_data[i + 3];

                                if bits & 0x80 != 0 {
                                    key_usage.push("digitalSignature".to_string());
                                }
                                if bits & 0x40 != 0 {
                                    key_usage.push("contentCommitment".to_string());
                                }
                                if bits & 0x20 != 0 {
                                    key_usage.push("keyEncipherment".to_string());
                                }
                                if bits & 0x10 != 0 {
                                    key_usage.push("dataEncipherment".to_string());
                                }
                                if bits & 0x08 != 0 {
                                    key_usage.push("keyAgreement".to_string());
                                }
                                if bits & 0x04 != 0 {
                                    key_usage.push("keyCertSign".to_string());
                                }
                                if bits & 0x02 != 0 {
                                    key_usage.push("cRLSign".to_string());
                                }

                                // Check second byte if present for last two bits
                                if i + 4 < ext_data.len() && ext_data[i + 1] > 1 {
                                    let bits2 = ext_data[i + 4];
                                    if bits2 & 0x80 != 0 {
                                        key_usage.push("encipherOnly".to_string());
                                    }
                                    if bits2 & 0x40 != 0 {
                                        key_usage.push("decipherOnly".to_string());
                                    }
                                }
                            }
                            break;
                        }
                    }
                }
                _ => {}
            }
        }
    }

    // Extract validity times from TBS certificate
    let validity = &cert.tbs_certificate.validity;

    // Convert x509-cert Time to SystemTime
    let not_before = validity.not_before.to_system_time();
    let not_after = validity.not_after.to_system_time();

    Ok((
        san_dns_names,
        san_ip_addresses,
        is_ca,
        key_usage,
        not_before,
        not_after,
    ))
}