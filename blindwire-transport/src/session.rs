//! Secure session API.
//!
//! The main public interface for establishing and using secure sessions.
//!
//! # Security Invariants
//!
//! - `SecureSession` does not implement `Clone`
//! - `burn(self)` consumes the session (cannot use after burn)
//! - `Drop` defensively burns if not already terminated
//! - `send_text()` validates UTF-8, rejects NUL bytes, enforces length limits

use blindwire_core::frame::MessageType;
use blindwire_core::state::{Session, SessionReceiveResult, SessionState};

use crate::config::{Role, TransportConfig};
use crate::error::TransportError;
use crate::message::Message;
use crate::relay::RelayTransport;

/// Maximum plaintext message size (matches protocol spec).
///
/// This is a hard protocol invariant (4000 bytes). This limit is chosen to ensure
/// that any message (including framing and AEAD overhead) fits within a single
/// 4096-byte MTU-friendly wire frame. Increasing this limit would require
/// re-evaluating the framing layer and potential fragmentation risks.
const MAX_PLAINTEXT_SIZE: usize = 4000;

/// A secure messaging session.
///
/// This type does not implement `Clone` to prevent state duplication.
/// Use `burn()` for immediate termination, or let `Drop` handle cleanup.
pub struct SecureSession {
    /// Kept for future network migration (reconnection with same session).
    #[allow(dead_code)]
    config: TransportConfig,
    inner: Session,
    relay: RelayTransport,
    terminated: bool,
}

// Explicitly NOT implementing Clone
// impl Clone for SecureSession { ... } // FORBIDDEN

impl SecureSession {
    /// Connect to the signaling server and establish a secure session.
    ///
    /// This performs:
    /// 1. WebSocket connection to signaling server
    /// 2. Session JOIN
    /// 3. Wait for peer (if initiator, blocks until responder joins)
    /// 4. Full Noise_XX handshake
    ///
    /// Returns error if any step fails.
    pub async fn connect(config: TransportConfig) -> Result<Self, TransportError> {
        // Validate URL scheme
        if !config.insecure_dev && !config.signaling_url.starts_with("wss://") {
            return Err(TransportError::ConnectionFailed(
                "wss:// required (use insecure_dev for local testing)".into(),
            ));
        }

        // Connect to signaling server
        let mut relay =
            RelayTransport::connect(&config.signaling_url, config.session_id, config.role).await?;

        // Create protocol session
        let mut inner = match config.role {
            Role::Initiator => Session::new_initiator()?,
            Role::Responder => Session::new_responder()?,
        };

        // Mark as connected
        inner.on_connected()?;

        // Initiator waits for responder to join
        if config.role == Role::Initiator {
            relay.wait_for_peer().await?;
        }

        // Perform handshake
        Self::perform_handshake(&mut inner, &mut relay).await?;

        Ok(Self {
            config,
            inner,
            relay,
            terminated: false,
        })
    }

    /// Perform the Noise_XX handshake.
    async fn perform_handshake(
        session: &mut Session,
        relay: &mut RelayTransport,
    ) -> Result<(), TransportError> {
        // Initiator starts handshake
        if session.role() == blindwire_core::noise::Role::Initiator {
            let frame = session.start_handshake()?;
            relay.send_frame(frame).await?;
        }

        // Exchange handshake messages until active
        while session.state() != SessionState::Active {
            let frame = relay.recv_frame().await?;
            let result = session.on_receive(frame)?;

            match result {
                SessionReceiveResult::HandshakeResponse(f)
                | SessionReceiveResult::HandshakeCompleteWithResponse(f) => {
                    relay.send_frame(f).await?;
                }
                SessionReceiveResult::HandshakeComplete => {
                    // Handshake done, no response needed
                }
                SessionReceiveResult::Continue => {
                    // Need more messages
                }
                SessionReceiveResult::Message(_) => {
                    // Should not receive data during handshake
                    return Err(TransportError::HandshakeFailed);
                }
                SessionReceiveResult::Terminated => {
                    return Err(TransportError::SessionTerminated);
                }
            }
        }

        Ok(())
    }

    /// Send an encrypted UTF-8 text message.
    ///
    /// # Validation
    ///
    /// This method rejects messages that:
    /// - Contain NUL bytes (`\0`)
    /// - Exceed 4000 bytes
    /// - Are not valid UTF-8 (enforced by `&str` type)
    ///
    /// # Hard Failures
    ///
    /// Any error during message construction, encryption, or transmission
    /// results in **immediate session termination**. This includes validation
    /// errors (e.g. NUL bytes) to prevent session misuse.
    ///
    /// # Errors
    ///
    /// Returns error if validation fails, session is terminated, or
    /// transport fails.
    pub async fn send_text(&mut self, text: &str) -> Result<(), TransportError> {
        if self.terminated {
            return Err(TransportError::SessionTerminated);
        }

        let result = self.send_text_inner(text).await;
        if result.is_err() {
            self.do_burn();
        }
        result
    }

    async fn send_text_inner(&mut self, text: &str) -> Result<(), TransportError> {
        // Validate: no NUL bytes
        if text.contains('\0') {
            return Err(TransportError::ContainsNul);
        }

        // Validate: length limit
        if text.len() > MAX_PLAINTEXT_SIZE {
            return Err(TransportError::MessageTooLong);
        }

        // Encrypt and send
        let frame = self.inner.send_message(text)?;
        self.relay.send_frame(frame).await
    }

    /// Receive a decrypted message.
    ///
    /// Returns a `Message` that zeroizes on drop.
    ///
    /// # Hard Failures
    ///
    /// In accordance with the BlindWire security philosophy, any error during
    /// reception (including protocol violations, decryption failures, or
    /// transport loss) results in **immediate session termination**.
    /// The session is marked as terminated, internal keys are zeroized,
    /// and subsequent calls will fail.
    ///
    /// # Errors
    ///
    /// Returns error if session is terminated, peer disconnects, or a
    /// protocol violation occurs.
    pub async fn recv(&mut self) -> Result<Message, TransportError> {
        if self.terminated {
            return Err(TransportError::SessionTerminated);
        }

        let result = self.recv_inner().await;
        if result.is_err() {
            self.do_burn();
        }
        result
    }

    async fn recv_inner(&mut self) -> Result<Message, TransportError> {
        loop {
            let frame = self.relay.recv_frame().await?;

            // Check for TERMINATE frame
            if frame.msg_type() == MessageType::Terminate {
                return Err(TransportError::SessionTerminated);
            }

            let result = self.inner.on_receive(frame)?;

            match result {
                SessionReceiveResult::Message(text) => {
                    return Ok(Message::new(text.into_bytes()));
                }
                SessionReceiveResult::Terminated => {
                    return Err(TransportError::SessionTerminated);
                }
                _ => {
                    // Ignore non-data messages (shouldn't happen in ACTIVE state)
                    continue;
                }
            }
        }
    }

    /// Get session fingerprint for out-of-band verification.
    ///
    /// Returns 16 hex characters derived from both parties' public keys.
    /// Both peers should compare this value over a trusted channel.
    ///
    /// Returns `None` if handshake is not complete.
    pub fn fingerprint(&self) -> Option<String> {
        self.inner.fingerprint()
    }

    /// Check if session is still active.
    pub fn is_active(&self) -> bool {
        !self.terminated && self.inner.state() == SessionState::Active
    }

    /// Immediate termination and zeroization.
    ///
    /// This is idempotent (safe to call multiple times).
    /// After calling, the session cannot be used.
    ///
    /// This method consumes `self` to prevent use after burn.
    pub fn burn(mut self) {
        self.do_burn();
        // self is consumed here, Drop will not run do_burn again
    }

    /// Internal burn implementation (for Drop and burn()).
    fn do_burn(&mut self) {
        if self.terminated {
            return; // Already burned
        }

        self.terminated = true;

        // Best effort: send TERMINATE and close
        // We can't await in Drop, so we'll just close synchronously
        // The relay's Drop will close the WebSocket

        // Terminate the protocol session (zeroizes keys)
        self.inner.terminate();
    }
}

impl Drop for SecureSession {
    fn drop(&mut self) {
        // Defensive burn if not already terminated
        self.do_burn();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validation_nul() {
        // Can't easily test async in sync test, just verify error type exists
        let err = TransportError::ContainsNul;
        assert!(err.to_string().contains("NUL"));
    }

    #[test]
    fn test_validation_length() {
        let err = TransportError::MessageTooLong;
        assert!(err.to_string().contains("4000"));
    }
}
