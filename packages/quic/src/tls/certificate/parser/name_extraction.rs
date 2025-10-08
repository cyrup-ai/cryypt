//! Certificate name attribute extraction operations
//!
//! This module provides functionality for extracting distinguished name (DN)
//! attributes from X.509 certificates using proper ASN.1 type handling.

use der::asn1::{Ia5StringRef, PrintableStringRef, Utf8StringRef};
use std::collections::HashMap;

/// Extract name attributes from x509-cert Name structure
pub fn extract_name_attributes(name: &x509_cert::name::Name, attrs: &mut HashMap<String, String>) {
    // Common OIDs for DN components
    const OID_CN: &str = "2.5.4.3"; // commonName
    const OID_O: &str = "2.5.4.10"; // organizationName
    const OID_OU: &str = "2.5.4.11"; // organizationalUnitName
    const OID_C: &str = "2.5.4.6"; // countryName
    const OID_ST: &str = "2.5.4.8"; // stateOrProvinceName
    const OID_L: &str = "2.5.4.7"; // localityName

    // Iterate through RDNs (Relative Distinguished Names)
    for rdn in &name.0 {
        // Each RDN contains one or more AttributeTypeAndValue
        for atv in rdn.0.iter() {
            let oid_string = atv.oid.to_string();

            // Extract the value as string using proper ASN.1 type handling
            // Try different ASN.1 string types as shown in x509-cert tests
            let string_value = if let Ok(ps) = PrintableStringRef::try_from(&atv.value) {
                Some(ps.to_string())
            } else if let Ok(utf8s) = Utf8StringRef::try_from(&atv.value) {
                Some(utf8s.to_string())
            } else if let Ok(ia5s) = Ia5StringRef::try_from(&atv.value) {
                Some(ia5s.to_string())
            } else {
                None
            };

            if let Some(value_str) = string_value {
                match oid_string.as_str() {
                    OID_CN => {
                        attrs.insert("CN".to_string(), value_str);
                    }
                    OID_O => {
                        attrs.insert("O".to_string(), value_str);
                    }
                    OID_OU => {
                        attrs.insert("OU".to_string(), value_str);
                    }
                    OID_C => {
                        attrs.insert("C".to_string(), value_str);
                    }
                    OID_ST => {
                        attrs.insert("ST".to_string(), value_str);
                    }
                    OID_L => {
                        attrs.insert("L".to_string(), value_str);
                    }
                    _ => {}
                }
            }
        }
    }
}
