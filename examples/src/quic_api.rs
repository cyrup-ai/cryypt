use cryypt::{Cryypt, QuicSend, QuicRecv, QuicServer, QuicClient};
use futures::stream::StreamExt;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Dummy certificate and private key for QUIC server
    let cert = b"dummy_cert".to_vec();
    let private_key = b"dummy_key".to_vec();
    let port = 4433;
    
    // QUIC server
    let server = Cryypt::quic()
        .server()
        .with_cert(cert.clone())
        .with_key(private_key.clone())
        .on_result(|result| {
            match result {
                Ok(result) => result,
                Err(_e) => {
                    log::error!("QUIC server bind error");
                    QuicServer::new() // Return unbound server (unwrapped value)
                }
            }
        })
        .bind(format!("127.0.0.1:{}", port))
        .await;

    // Simulate server running (in a real app, you'd spawn a task)
    println!("QUIC server bound to: 127.0.0.1:{}", port);
    println!("Server ready: {}", server.is_bound());

    // QUIC client
    let client = Cryypt::quic()
        .client()
        .with_server_name("example.com")
        .on_result(|result| {
            match result {
                Ok(result) => result,
                Err(_e) => {
                    log::error!("Connection failed");
                    QuicClient::new() // Return unconnected client
                }
            }
        })
        .connect("127.0.0.1:4433")
        .await;

    // Open bidirectional stream
    let (send, recv) = client
        .on_result(|result| {
            match result {
                Ok(result) => result,
                Err(_e) => {
                    log::error!("Failed to open stream");
                    (QuicSend::new(), QuicRecv::new()) // Empty streams
                }
            }
        })
        .open_bi()
        .await;

    // Send data
    send
        .on_result(|result| {
            match result {
                Ok(result) => result,
                Err(_e) => {
                    log::error!("Failed to send data");
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
                Ok(chunk) => Some(chunk),
                Err(_e) => {
                    log::error!("Receive error");
                    None
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