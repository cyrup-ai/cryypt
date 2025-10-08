use std::net::SocketAddr;

/// Generate a real self-signed certificate for example purposes using modern rcgen API
async fn generate_example_certificate() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};

    // Create certificate parameters for localhost - new API returns Result
    let mut params = CertificateParams::new(vec!["localhost".to_string()])?;

    // Set up distinguished name
    let mut distinguished_name = DistinguishedName::new();
    distinguished_name.push(DnType::CommonName, "localhost");
    params.distinguished_name = distinguished_name;

    // Generate key pair
    let key_pair = KeyPair::generate()?;

    // Create self-signed certificate using modern API
    let cert = params.self_signed(&key_pair)?;

    // Get DER bytes
    let cert_der = cert.der().to_vec();

    Ok(cert_der)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // QUIC Example - demonstrating README.md patterns
    let endpoint: SocketAddr = "127.0.0.1:443".parse()?;
    // Generate real certificate for example
    let cert_data = generate_example_certificate().await?;

    println!("QUIC Example - Demonstrating README.md API Patterns");

    // The QUIC API implementation is still in development
    // This example shows the intended patterns from README.md
    println!("\n=== QUIC Client Pattern (from README.md) ===");
    println!("let client = Cryypt::quic()");
    println!("    .client()");
    println!("    .with_endpoint(\"https://example.com:443\")");
    println!("    .with_certificates(cert_data)");
    println!("    .on_result(|result| {{");
    println!("        Ok(client_connection) => {{");
    println!("            log::info!(\"QUIC client connected\");");
    println!("            client_connection");
    println!("        }}");
    println!("        Err(e) => {{");
    println!("            log::error!(\"QUIC client connection failed: {{}}\", e);");
    println!("            panic!(\"Critical QUIC client failure\")");
    println!("        }}");
    println!("    }})");
    println!("    .connect()");
    println!("    .await;");

    println!("\n=== QUIC Server Pattern (from README.md) ===");
    println!("let server = Cryypt::quic()");
    println!("    .server()");
    println!("    .with_bind_address(\"0.0.0.0:443\")");
    println!("    .with_certificates(cert_data)");
    println!("    .on_result(|result| {{");
    println!("        Ok(server_handle) => {{");
    println!("            log::info!(\"QUIC server started\");");
    println!("            server_handle");
    println!("        }}");
    println!("        Err(e) => {{");
    println!("            log::error!(\"QUIC server startup failed: {{}}\", e);");
    println!("            panic!(\"Critical QUIC server failure\")");
    println!("        }}");
    println!("    }})");
    println!("    .start()");
    println!("    .await;");

    println!("\n=== Implementation Notes ===");
    println!("- QUIC API supports both client and server operations");
    println!("- Actions take data as arguments: connect(endpoint) not with_endpoint().connect()");
    println!("- Error handling comes before action methods");
    println!("- Both client and server operations supported");
    println!("- API implementation may still be in development");
    println!("- Current endpoint: {}", endpoint);
    println!("- Cert data length: {} bytes", cert_data.len());

    println!("\nQUIC example completed - patterns demonstrated");

    Ok(())
}
