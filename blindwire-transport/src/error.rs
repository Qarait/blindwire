//! Transport errors.

use std::fmt;

/// Errors that can occur during transport operations.
///
/// In BlindWire, almost all errors are terminal. Any protocol violation or
/// validation failure results in the session being burned immediately.
#[derive(Debug)]
pub enum TransportError {
    // --- Connection & Setup ---
    /// Failed to establish WebSocket connection.
    ConnectionFailed(String),
    /// Noise handshake failed.
    HandshakeFailed,
    /// Operation timed out.
    Timeout,

    // --- Protocol Violations (Terminal) ---
    /// Protocol-level error from blindwire-core.
    Protocol(blindwire_core::ProtocolError),
    /// Unexpected server response.
    UnexpectedResponse(u8),

    // --- Validation Failures (Programmer Error / Terminal) ---
    /// Invalid message: contains NUL bytes.
    ContainsNul,
    /// Invalid message: exceeds maximum length (4000 bytes).
    MessageTooLong,
    /// Invalid message: not valid UTF-8.
    InvalidUtf8,

    // --- Lifecycle & Transport ---
    /// Session has been terminated or burned.
    SessionTerminated,
    /// WebSocket error.
    WebSocket(String),
    /// Peer disconnected gracefully or connection lost.
    PeerDisconnected,
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ConnectionFailed(msg) => write!(f, "connection failed: {}", msg),
            Self::HandshakeFailed => write!(f, "handshake failed"),
            Self::Protocol(e) => write!(f, "protocol error: {:?}", e),
            Self::SessionTerminated => write!(f, "session terminated"),
            Self::Timeout => write!(f, "operation timed out"),
            Self::ContainsNul => write!(f, "message contains NUL bytes"),
            Self::MessageTooLong => write!(f, "message exceeds 4000 byte limit"),
            Self::InvalidUtf8 => write!(f, "message is not valid UTF-8"),
            Self::WebSocket(msg) => write!(f, "websocket error: {}", msg),
            Self::PeerDisconnected => write!(f, "peer disconnected"),
            Self::UnexpectedResponse(op) => write!(f, "unexpected server response: 0x{:02x}", op),
        }
    }
}

impl std::error::Error for TransportError {}

impl From<blindwire_core::ProtocolError> for TransportError {
    fn from(e: blindwire_core::ProtocolError) -> Self {
        Self::Protocol(e)
    }
}
