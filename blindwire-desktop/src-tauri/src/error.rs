use serde::{Serialize, Deserialize};
use blindwire_transport::TransportError;

/// Strictly structured, UI-safe error returned by all Tauri commands.
/// Never leaks Rust panics, stack traces, certificates, or raw crypto secrets to the frontend.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AppError {
    /// A stable enum-like string identifier for reliable UI branching (e.g., "INVITE_INVALID").
    pub code: String,
    /// A safe, human-readable message intended for display.
    pub message: String,
    /// True if the UI can safely offer a "Retry" button.
    pub retryable: bool,
}

impl AppError {
    pub fn new(code: &str, message: &str, retryable: bool) -> Self {
        Self {
            code: code.to_string(),
            message: message.to_string(),
            retryable,
        }
    }

    pub fn unhandled() -> Self {
        Self::new("UNKNOWN_ERROR", "An unexpected error occurred.", false)
    }
}

// Map from blindwire-core::invite::InviteError to AppError
impl From<blindwire_core::invite::InviteError> for AppError {
    fn from(err: blindwire_core::invite::InviteError) -> Self {
        use blindwire_core::invite::InviteError::*;
        match err {
            InvalidUriFormat | MissingRequiredField(_) | UnknownOrDuplicateField(_) | InvalidVersion | OversizedField(_) | InvalidEncoding(_) => {
                Self::new("INVITE_INVALID", "This invite link is invalid or corrupted.", false)
            }
            InvalidRelayUrl => Self::new("INVITE_INVALID", "This invite specifies a malformed relay server.", false),
            ExpiredToken => Self::new("INVITE_EXPIRED", "This invite link has expired.", false),
            CustomRelayRequiresPin => Self::new("CUSTOM_RELAY_PIN_REQUIRED", "This custom room requires a security pin.", false),
            OfficialRelayMustNotHavePin => Self::new("INVITE_INVALID", "This invite link is malformed (pin injection detected).", false),
        }
    }
}

// Map from blindwire-transport::TransportError to AppError
impl From<TransportError> for AppError {
    fn from(err: TransportError) -> Self {
        match err {
            TransportError::ConnectionFailed(_) | TransportError::Timeout => {
                Self::new("RELAY_UNREACHABLE", "Could not reach the relay server. Please check your connection.", true)
            }
            TransportError::HandshakeFailed => {
                Self::new("HANDSHAKE_FAILED", "The secure handshake failed. The server identity may have changed.", false)
            }
            TransportError::RateLimitExceeded => {
                Self::new("RATE_LIMITED", "Too many connection attempts. Please wait a moment before retrying.", true)
            }
            TransportError::SessionTerminated | TransportError::PeerDisconnected => {
                Self::new("SESSION_ENDED", "The connection ended unexpectedly.", false)
            }
            TransportError::MessageTooLong => {
                Self::new("MESSAGE_TOO_LONG", "Your message exceeds the 4000 character limit.", true)
            }
            TransportError::ContainsNul => {
                Self::new("INVALID_MESSAGE", "Your message contains invalid characters.", true)
            }
            TransportError::Protocol(_) | TransportError::UnexpectedResponse(_) | TransportError::VersionMismatch => {
                Self::new("PROTOCOL_ERROR", "A protocol error occurred. The session has been terminated.", false)
            }
            TransportError::WebSocket(_) | TransportError::InvalidUtf8 => {
                Self::new("CONNECTION_ERROR", "A low-level connection error occurred.", true)
            }
        }
    }
}
