//! Transport configuration.

/// Role in the session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Session creator. Sends first handshake message.
    Initiator,
    /// Session joiner. Receives first handshake message.
    Responder,
}

impl Role {
    /// Get the signaling protocol role byte.
    pub(crate) fn as_byte(self) -> u8 {
        match self {
            Role::Initiator => b'i',
            Role::Responder => b'r',
        }
    }
}

/// Configuration for establishing a secure session.
///
/// This struct does not implement `Clone` to prevent accidental duplication
/// of session identifiers.
#[derive(Debug)]
pub struct TransportConfig {
    /// Signaling server URL (e.g., "wss://server:8080" or "ws://localhost:8080")
    pub signaling_url: String,
    /// 32-byte session identifier (shared out-of-band between peers)
    pub session_id: [u8; 32],
    /// Role in the session (Initiator or Responder)
    pub role: Role,
    /// Allow insecure ws:// connections (for localhost development only)
    pub insecure_dev: bool,
    /// Path to persist TOFU pins (for custom servers)
    pub pins_path: Option<std::path::PathBuf>,
}

impl TransportConfig {
    /// Create a new configuration for an initiator.
    pub fn initiator(signaling_url: impl Into<String>, session_id: [u8; 32]) -> Self {
        Self {
            signaling_url: signaling_url.into(),
            session_id,
            role: Role::Initiator,
            insecure_dev: false,
            pins_path: None,
        }
    }

    /// Create a new configuration for a responder.
    pub fn responder(signaling_url: impl Into<String>, session_id: [u8; 32]) -> Self {
        Self {
            signaling_url: signaling_url.into(),
            session_id,
            role: Role::Responder,
            insecure_dev: false,
            pins_path: None,
        }
    }

    /// Set the path for persisting TOFU pins.
    pub fn with_pins_path(mut self, path: std::path::PathBuf) -> Self {
        self.pins_path = Some(path);
        self
    }

    /// Allow insecure ws:// connections (for localhost development only).
    ///
    /// # Security Warning
    ///
    /// This disables transport encryption. Only use for local testing.
    pub fn with_insecure_dev(mut self) -> Self {
        self.insecure_dev = true;
        self
    }
}
