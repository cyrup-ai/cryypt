use cryypt::Cryypt;

let encrypted = Cryypt::cipher()
    .aes()
    .with_key(key)
    .on_result(|result| {
        Ok => result,
        Err(e) => {
            log::error!("Encryption failed: {}", e);
            Vec::new() // Return empty on error
        }
    })
    .encrypt(b"Secret message")
    .await;