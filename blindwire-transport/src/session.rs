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
use std::time::Duration;

use crate::config::{Role, TransportConfig};
use crate::error::TransportError;
use crate::message::Message;
use crate::relay::RelayTransport;

/// Maximum plaintext message size (matches protocol spec).
///
/// This is a hard protocol invariant (4000 bytes). This limit is chosen to ensure
/// that any message (including framing and AEAD overhead) fits within a single
/// 4096-byte MTU-friendly wire frame. Increasing this limit would require
fn validate_signaling_url(config: &TransportConfig) -> Result<(), TransportError> {
    let url = url::Url::parse(&config.signaling_url)
        .map_err(|_| TransportError::ConnectionFailed("invalid signaling server URL".into()))?;

    if url.scheme() == "wss" {
        return Ok(());
    }

    let is_loopback = match url.host() {
        Some(url::Host::Domain(host)) => host.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(address)) => address.is_loopback(),
        Some(url::Host::Ipv6(address)) => address.is_loopback(),
        None => false,
    };

    if cfg!(debug_assertions) && config.insecure_dev && url.scheme() == "ws" && is_loopback {
        return Ok(());
    }

    Err(TransportError::ConnectionFailed(
        "wss:// required; ws:// is limited to localhost debug builds".into(),
    ))
}

/// re-evaluating the framing layer and potential fragmentation risks.
const MAX_PLAINTEXT_SIZE: usize = 4000;
const HANDSHAKE_DEADLINE: Duration = Duration::from_secs(30);

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

impl std::fmt::Debug for SecureSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecureSession")
            .field("config", &self.config)
            .field("inner", &self.inner)
            .field("relay", &self.relay)
            .field("terminated", &self.terminated)
            .finish()
    }
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
    pub async fn connect(
        config: TransportConfig,
    ) -> Result<(Self, Option<[u8; 32]>), TransportError> {
        validate_signaling_url(&config)?;

        // Connect to signaling server
        let (relay, token) = RelayTransport::connect(&config).await?;

        let inner = Self::new_protocol_session(config.role)?;

        Ok((
            Self {
                config,
                inner,
                relay,
                terminated: false,
            },
            token,
        ))
    }

    fn new_protocol_session(role: Role) -> Result<Session, TransportError> {
        let mut session = match role {
            Role::Initiator => Session::new_initiator()?,
            Role::Responder => Session::new_responder()?,
        };
        session.on_connected()?;
        Ok(session)
    }

    /// Complete Noise XX and wait for the relay's two-sided confirmation.
    /// All responder attempts share this one 30-second deadline.
    pub async fn handshake(&mut self) -> Result<(), TransportError> {
        if self.terminated {
            return Err(TransportError::SessionTerminated);
        }

        let result = match tokio::time::timeout(
            HANDSHAKE_DEADLINE,
            self.handshake_until_confirmed(),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => Err(TransportError::Timeout),
        };

        if result.is_err() {
            self.do_burn();
        }
        result
    }

    async fn handshake_until_confirmed(&mut self) -> Result<(), TransportError> {
        loop {
            if self.config.role == Role::Initiator {
                match self.relay.wait_for_peer().await {
                    Ok(()) => {}
                    Err(TransportError::PeerDisconnected) => {
                        self.reset_initiator_noise()?;
                        continue;
                    }
                    Err(error) => return Err(error),
                }
            }

            match Self::perform_handshake(&mut self.inner, &mut self.relay).await {
                Ok(()) => {}
                Err(TransportError::PeerDisconnected) if self.config.role == Role::Initiator => {
                    self.reset_initiator_noise()?;
                    continue;
                }
                Err(error) => return Err(error),
            }

            self.relay.send_handshake_complete().await?;
            match self.relay.wait_handshake_confirmed().await {
                Ok(()) => return Ok(()),
                Err(TransportError::PeerDisconnected) if self.config.role == Role::Initiator => {
                    self.reset_initiator_noise()?;
                }
                Err(error) => return Err(error),
            }
        }
    }

    fn reset_initiator_noise(&mut self) -> Result<(), TransportError> {
        debug_assert_eq!(self.config.role, Role::Initiator);
        self.inner.terminate();
        self.inner = Self::new_protocol_session(Role::Initiator)?;
        Ok(())
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
    #[test]
    fn secure_websocket_urls_are_accepted() {
        let config = TransportConfig::initiator("wss://relay.blindwire.net", [0; 32]);
        assert!(validate_signaling_url(&config).is_ok());
    }

    #[test]
    fn insecure_remote_websocket_is_rejected_even_when_requested() {
        let config =
            TransportConfig::initiator("ws://example.com:8080", [0; 32]).with_insecure_dev();
        assert!(validate_signaling_url(&config).is_err());
    }

    #[test]
    fn insecure_local_websocket_depends_on_debug_build() {
        for url in [
            "ws://localhost:8080",
            "ws://127.0.0.1:8080",
            "ws://[::1]:8080",
        ] {
            let config = TransportConfig::initiator(url, [0; 32]).with_insecure_dev();
            if cfg!(debug_assertions) {
                assert!(validate_signaling_url(&config).is_ok(), "{url}");
            } else {
                assert!(validate_signaling_url(&config).is_err(), "{url}");
            }
        }
    }

    #[test]
    fn insecure_local_websocket_requires_explicit_opt_in() {
        let config = TransportConfig::initiator("ws://127.0.0.1:8080", [0; 32]);
        assert!(validate_signaling_url(&config).is_err());
    }
}
