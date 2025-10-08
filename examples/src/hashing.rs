let hash = Cryypt::hash()
    .sha256()
    .on_result(|result| {
        result
            .map(|result| result.to_vec())
            .unwrap_or_else(|e| {
                log::error!("Hash computation failed: {}", e);
                Vec::new()
            })
    })
    .compute(b"Hello, World!")
    .await;