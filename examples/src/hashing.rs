let hash = Cryypt::hash()
    .sha256()
    .on_result(|result| {
        Ok(result) => result.to_vec(),
        Err(e) => {
            log::error!("Hash computation failed: {}", e);
            Vec::new() // Return empty hash on error
        }
    })
    .compute(b"Hello, World!")
    .await;