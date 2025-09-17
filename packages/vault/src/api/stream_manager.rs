//! Stream ID manager for QUIC connections with production-ready implementation

/// Stream ID manager for QUIC connections with production-ready implementation
pub struct StreamIdManager {
    next_client_bidi: std::sync::atomic::AtomicU64,
    next_client_uni: std::sync::atomic::AtomicU64,
    next_server_bidi: std::sync::atomic::AtomicU64,
    next_server_uni: std::sync::atomic::AtomicU64,
}

impl StreamIdManager {
    /// Create new stream ID manager
    pub fn new() -> Self {
        Self {
            next_client_bidi: std::sync::atomic::AtomicU64::new(0),
            next_client_uni: std::sync::atomic::AtomicU64::new(2),
            next_server_bidi: std::sync::atomic::AtomicU64::new(1),
            next_server_uni: std::sync::atomic::AtomicU64::new(3),
        }
    }

    /// Get next client-initiated bidirectional stream ID
    pub fn next_client_bidi_stream_id(&self) -> u64 {
        self.next_client_bidi
            .fetch_add(4, std::sync::atomic::Ordering::Relaxed)
    }

    /// Get next client-initiated unidirectional stream ID
    pub fn next_client_uni_stream_id(&self) -> u64 {
        self.next_client_uni
            .fetch_add(4, std::sync::atomic::Ordering::Relaxed)
    }

    /// Get next server-initiated bidirectional stream ID
    pub fn next_server_bidi_stream_id(&self) -> u64 {
        self.next_server_bidi
            .fetch_add(4, std::sync::atomic::Ordering::Relaxed)
    }

    /// Get next server-initiated unidirectional stream ID
    pub fn next_server_uni_stream_id(&self) -> u64 {
        self.next_server_uni
            .fetch_add(4, std::sync::atomic::Ordering::Relaxed)
    }

    /// Check if stream ID is valid for client-initiated bidirectional streams
    pub fn is_client_bidi(&self, stream_id: u64) -> bool {
        stream_id.is_multiple_of(4)
    }

    /// Check if stream ID is valid for client-initiated unidirectional streams
    pub fn is_client_uni(&self, stream_id: u64) -> bool {
        stream_id % 4 == 2
    }

    /// Check if stream ID is valid for server-initiated bidirectional streams
    pub fn is_server_bidi(&self, stream_id: u64) -> bool {
        stream_id % 4 == 1
    }

    /// Check if stream ID is valid for server-initiated unidirectional streams
    pub fn is_server_uni(&self, stream_id: u64) -> bool {
        stream_id % 4 == 3
    }
}

impl Default for StreamIdManager {
    fn default() -> Self {
        Self::new()
    }
}
