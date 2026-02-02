//! Protocol errors.
//!
//! All errors are terminal. There is no recovery.
//! When an error occurs, the session must be terminated and keys zeroized.

use std::fmt;

/// All possible protocol errors.
///
/// Each error variant causes immediate session termination.
/// No error is "recoverable" or "retryable".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolError {
    /// Message length exceeds maximum (4096 bytes)
    MessageTooLarge,

    /// Message body is empty (length < 1)
    MessageEmpty,

    /// Unknown message type byte
    UnknownMessageType,

    /// Message type not allowed in current state
    UnexpectedMessageType,

    /// Noise handshake failed
    HandshakeFailed,

    /// Noise decryption/authentication failed
    DecryptionFailed,

    /// Plaintext is not valid UTF-8
    InvalidUtf8,

    /// Plaintext contains NUL byte
    NulByteInPlaintext,

    /// Plaintext is empty
    EmptyPlaintext,

    /// Plaintext exceeds maximum size
    PlaintextTooLarge,

    /// TERMINATE message has non-empty payload
    TerminatePayloadNotEmpty,

    /// Session has already terminated
    SessionTerminated,

    /// Handshake timeout exceeded
    HandshakeTimeout,

    /// Idle timeout exceeded
    IdleTimeout,

    /// Session TTL exceeded
    SessionTtlExceeded,

    /// Transport error (connection lost)
    TransportError,

    /// Internal error (should never happen)
    InternalError,
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Deliberately terse. Do not leak details.
        match self {
            Self::MessageTooLarge => write!(f, "message too large"),
            Self::MessageEmpty => write!(f, "message empty"),
            Self::UnknownMessageType => write!(f, "unknown message type"),
            Self::UnexpectedMessageType => write!(f, "unexpected message type"),
            Self::HandshakeFailed => write!(f, "handshake failed"),
            Self::DecryptionFailed => write!(f, "decryption failed"),
            Self::InvalidUtf8 => write!(f, "invalid utf-8"),
            Self::NulByteInPlaintext => write!(f, "nul byte in plaintext"),
            Self::EmptyPlaintext => write!(f, "empty plaintext"),
            Self::PlaintextTooLarge => write!(f, "plaintext too large"),
            Self::TerminatePayloadNotEmpty => write!(f, "terminate payload not empty"),
            Self::SessionTerminated => write!(f, "session terminated"),
            Self::HandshakeTimeout => write!(f, "handshake timeout"),
            Self::IdleTimeout => write!(f, "idle timeout"),
            Self::SessionTtlExceeded => write!(f, "session ttl exceeded"),
            Self::TransportError => write!(f, "transport error"),
            Self::InternalError => write!(f, "internal error"),
        }
    }
}

impl std::error::Error for ProtocolError {}
