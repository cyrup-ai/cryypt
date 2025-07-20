use cryypt::{Cryypt, on_result};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // QUIC server with retry on different port
    let mut port = 4433;
    let server = loop {
        let result = Cryypt::quic()
            .server()
            .with_cert(cert.clone())
            .with_key(private_key.clone())
            .on_result(|result| {
                Ok => result,
                Err(e) => {
                    log::error!("QUIC error: {}", e);
                    return Err(e)
                }
            })
            .bind(format!("127.0.0.1:{}", port))
            .await;
        
        match result {
            Ok(server) => break server,
            Err(e) => {
                log::error!("Server bind failed on port {}: {}", port, e);
                port += 1;
                if port > 4440 {
                    log::error!("Failed to bind to any port 4433-4440");
                    break Cryypt::quic().server(); // Return unbound server
                }
            }
        }
    };

    // QUIC client
    let client = Cryypt::quic()
        .client()
        .with_server_name("example.com")
        .on_result(|result| {
            Ok => result,
            Err(e) => {
                log::error!("Connection failed: {}", e);
                Cryypt::quic().client() // Return unconnected client
            }
        })
        .connect("127.0.0.1:4433")
        .await;

    // Open bidirectional stream
    let (send, recv) = client
        .on_result(|result| {
            Ok => result,
            Err(e) => {
                log::error!("Failed to open stream: {}", e);
                (QuicSend::new(), QuicRecv::new()) // Empty streams
            }
        })
        .open_bi()
        .await;

    // Send data
    send
        .on_result(|result| {
            match result {
                Ok(result) => result,
                Err(e) => {
                    log::error!("Failed to send data: {}", e);
                    ()
                }
            }
        })
        .write_all(b"Hello QUIC")
        .await;

    // Receive streamed data
    let mut data = Vec::new();
    let mut recv_stream = recv
        .on_chunk(|chunk| {
            match chunk {
                Ok(chunk) => chunk,
                Err(e) => {
                    log::error!("Receive error: {}", e);
                    return
                }
            }
        })
        .stream();

    while let Some(chunk) = recv_stream.next().await {
        data.extend_from_slice(&chunk);
    }
    
    println!("Received {} bytes via QUIC", data.len());
    println!("Data: {}", String::from_utf8_lossy(&data));
    
    Ok(())
}