# cryypt_quic

QUIC transport protocol with built-in encryption for the Cryypt cryptography suite.

## Installation

```toml
[dependencies]
cryypt_quic = "0.1"
```

## API Examples

### QUIC Server and Client

```rust
use cryypt::Cryypt;

// QUIC server with retry on different port
let mut port = 4433;
let server = loop {
    let result = Cryypt::quic()
        .server()
        .with_cert(cert.clone())
        .with_key(private_key.clone())
        .on_result(|result| match result {
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
    .on_result(|result| match result {
        Ok => result,
        Err(e) => {
            log::error!("Connection failed: {}", e);
            Cryypt::quic().client() // Return unconnected client
        }
    })
    .connect("127.0.0.1:4433")
    .await; // Returns fully unwrapped value - no Result wrapper

// Open bidirectional stream
let (send, recv) = client
    .on_result(|result| match result {
        Ok => result,
        Err(e) => {
            log::error!("Failed to open stream: {}", e);
            (QuicSend::new(), QuicRecv::new()) // Empty streams
        }
    })
    .open_bi()
    .await; // Returns fully unwrapped value - no Result wrapper

// Send data
send
    .on_result(|result| match result {
        Ok => result,
        Err(e) => {
            log::error!("Failed to send data: {}", e);
            ()
        }
    })
    .write_all(b"Hello QUIC")
    .await; // Returns fully unwrapped value - no Result wrapper

// Receive streamed data
let mut data = Vec::new();
let mut recv_stream = recv
    .on_chunk(|chunk| {
        Ok => chunk.into(),
        Err(e) => {
            log::error!("Receive error: {}", e);
            BadChunk::from_error(e)
        }
    })
    .stream(); // Returns Stream<Item = Vec<u8>> - fully unwrapped chunks

while let Some(chunk) = recv_stream.next().await {
    // chunk is Vec<u8> - already unwrapped by on_chunk handler
    data.extend_from_slice(&chunk);
}
```