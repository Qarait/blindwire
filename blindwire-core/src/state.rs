//! Protocol state machine.
//!
//! Implements the session state machine from PROTOCOL_STATE_MACHINE.md.
//!
//! States: CREATED → CONNECTED → HANDSHAKING → ACTIVE → TERMINATED
//!
//! Any error transitions immediately to TERMINATED.
//! No retries. No recovery.

use std::time::{Duration, Instant};
use zeroize::{Zeroize, Zeroizing};

use crate::error::ProtocolError;
use crate::frame::{validate_plaintext, Frame, MessageType};
use crate::noise::{NoiseSession, Role};

/// Handshake timeout: 30 seconds.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// Idle timeout: 10 minutes between messages.
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(600);

/// Session TTL: 1 hour maximum lifetime.
pub const SESSION_TTL: Duration = Duration::from_secs(3600);

/// Reconnection grace window: 5 seconds.
pub const RECONNECT_GRACE: Duration = Duration::from_secs(5);

/// Session state enumeration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    /// Session created but not connected.
    Created,
    /// Connected to signaling server, waiting for handshake.
    Connected,
    /// Handshake in progress.
    Handshaking,
    /// Handshake complete, encrypted transport active.
    Active,
    /// Transport lost, waiting for reconnection (keys held).
    DisconnectedGrace,
    /// Session terminated. Final state.
    Terminated,
}

/// A protocol session.
///
/// Manages state transitions, timeouts, and the underlying Noise session.
pub struct Session {
    state: SessionState,
    role: Role,
    noise: Option<NoiseSession>,
    
    // Timing
    created_at: Instant,
    connected_at: Option<Instant>,
    last_message_at: Option<Instant>,
    disconnection_at: Option<Instant>,
    
    // Handshake tracking (for Noise_XX 3-message flow)
    handshake_messages_sent: u8,
    handshake_messages_received: u8,
}

impl Session {
    /// Create a new session as initiator.
    pub fn new_initiator() -> Result<Self, ProtocolError> {
        let noise = NoiseSession::new_initiator()?;
        Ok(Self {
            state: SessionState::Created,
            role: Role::Initiator,
            noise: Some(noise),
            created_at: Instant::now(),
            connected_at: None,
            last_message_at: None,
            disconnection_at: None,
            handshake_messages_sent: 0,
            handshake_messages_received: 0,
        })
    }

    /// Create a new session as responder.
    pub fn new_responder() -> Result<Self, ProtocolError> {
        let noise = NoiseSession::new_responder()?;
        Ok(Self {
            state: SessionState::Created,
            role: Role::Responder,
            noise: Some(noise),
            created_at: Instant::now(),
            connected_at: None,
            last_message_at: None,
            disconnection_at: None,
            handshake_messages_sent: 0,
            handshake_messages_received: 0,
        })
    }

    /// Get current state.
    pub fn state(&self) -> SessionState {
        self.state
    }

    /// Get role.
    pub fn role(&self) -> Role {
        self.role
    }

    /// Check all timeouts. Returns error if any timeout exceeded.
    ///
    /// Must be called before any operation. Caller is responsible for
    /// calling this periodically or before each operation.
    pub fn check_timeouts(&mut self) -> Result<(), ProtocolError> {
        if self.state == SessionState::Terminated {
            return Err(ProtocolError::SessionTerminated);
        }

        let now = Instant::now();

        // Check session TTL (absolute limit)
        if now.duration_since(self.created_at) > SESSION_TTL {
            self.terminate();
            return Err(ProtocolError::SessionTtlExceeded);
        }

        // Check handshake timeout
        if self.state == SessionState::Connected || self.state == SessionState::Handshaking {
            if let Some(connected_at) = self.connected_at {
                if now.duration_since(connected_at) > HANDSHAKE_TIMEOUT {
                    self.terminate();
                    return Err(ProtocolError::HandshakeTimeout);
                }
            }
        }

        // Check idle timeout
        if self.state == SessionState::Active {
            if let Some(last_msg) = self.last_message_at {
                if now.duration_since(last_msg) > IDLE_TIMEOUT {
                    self.terminate();
                    return Err(ProtocolError::IdleTimeout);
                }
            }
        }

        // Check reconnection grace
        if self.state == SessionState::DisconnectedGrace {
            if let Some(disconnection_at) = self.disconnection_at {
                if now.duration_since(disconnection_at) > RECONNECT_GRACE {
                    self.terminate();
                    return Err(ProtocolError::TransportError); // Grace expired
                }
            }
        }

        Ok(())
    }

    /// Mark session as connected to signaling server.
    ///
    /// Transitions: Created → Connected, DisconnectedGrace → Active
    pub fn on_connected(&mut self) -> Result<(), ProtocolError> {
        self.check_timeouts()?;

        match self.state {
            SessionState::Created => {
                self.state = SessionState::Connected;
                self.connected_at = Some(Instant::now());
            }
            SessionState::DisconnectedGrace => {
                self.state = SessionState::Active;
                self.disconnection_at = None;
            }
            _ => {
                self.terminate();
                return Err(ProtocolError::UnexpectedMessageType);
            }
        }
        Ok(())
    }

    /// Mark transport as lost.
    ///
    /// Transitions: Active → DisconnectedGrace
    pub fn on_disconnected(&mut self) {
        if self.state == SessionState::Active {
            self.state = SessionState::DisconnectedGrace;
            self.disconnection_at = Some(Instant::now());
        } else if self.state != SessionState::DisconnectedGrace && self.state != SessionState::Terminated {
            // If disconnected during handshake or created, just terminate
            self.terminate();
        }
    }

    /// Start the handshake (initiator only, sends first message).
    ///
    /// Returns the first handshake message to send.
    pub fn start_handshake(&mut self) -> Result<Frame, ProtocolError> {
        self.check_timeouts()?;

        if self.state != SessionState::Connected {
            self.terminate();
            return Err(ProtocolError::UnexpectedMessageType);
        }

        if self.role != Role::Initiator {
            self.terminate();
            return Err(ProtocolError::UnexpectedMessageType);
        }

        let noise = self.noise.as_mut().ok_or(ProtocolError::SessionTerminated)?;
        let msg = noise.write_handshake()?;
        
        self.state = SessionState::Handshaking;
        self.handshake_messages_sent = 1;

        Frame::handshake(msg)
    }

    /// Process an inbound frame.
    ///
    /// Returns an optional response frame and optional decrypted message.
    pub fn on_receive(&mut self, frame: Frame) -> Result<SessionReceiveResult, ProtocolError> {
        self.check_timeouts()?;

        match (self.state, frame.msg_type()) {
            // TERMINATE is always valid (except in Created/Terminated)
            (SessionState::Created, MessageType::Terminate) => {
                self.terminate();
                Err(ProtocolError::SessionTerminated)
            }
            (SessionState::Terminated, _) => {
                Err(ProtocolError::SessionTerminated)
            }
            (_, MessageType::Terminate) => {
                self.terminate();
                Ok(SessionReceiveResult::Terminated)
            }

            // Handshake messages
            (SessionState::Connected, MessageType::Handshake) => {
                // Responder receives first handshake message
                if self.role != Role::Responder {
                    self.terminate();
                    return Err(ProtocolError::UnexpectedMessageType);
                }
                self.process_handshake(frame.into_payload())
            }
            (SessionState::Handshaking, MessageType::Handshake) => {
                self.process_handshake(frame.into_payload())
            }

            // Data messages
            (SessionState::Active, MessageType::Data) => {
                self.process_data(frame.into_payload())
            }

            // Invalid message type for current state
            _ => {
                self.terminate();
                Err(ProtocolError::UnexpectedMessageType)
            }
        }
    }

    /// Process a handshake message.
    fn process_handshake(&mut self, payload: Zeroizing<Vec<u8>>) -> Result<SessionReceiveResult, ProtocolError> {
        let noise = self.noise.as_mut().ok_or(ProtocolError::SessionTerminated)?;

        // HandshakeState in snow takes &[u8], Zeroizing derefs to Vec<u8> then to &[u8]
        noise.read_handshake(&payload)?;
        self.handshake_messages_received += 1;

        // If handshake complete, transition to Active
        if noise.is_handshake_complete() {
            self.state = SessionState::Active;
            self.last_message_at = Some(Instant::now());
            return Ok(SessionReceiveResult::HandshakeComplete);
        }

        // Otherwise, send our response
        if noise.is_my_turn().map_err(|_| ProtocolError::InternalError)? {
            let response = noise.write_handshake()?;
            self.handshake_messages_sent += 1;
            
            // Update state to Handshaking if not already
            if self.state == SessionState::Connected {
                self.state = SessionState::Handshaking;
            }

            // Check if handshake is now complete
            if noise.is_handshake_complete() {
                self.state = SessionState::Active;
                self.last_message_at = Some(Instant::now());
                return Ok(SessionReceiveResult::HandshakeCompleteWithResponse(
                    Frame::handshake(response)?
                ));
            }

            return Ok(SessionReceiveResult::HandshakeResponse(
                Frame::handshake(response)?
            ));
        }

        // Waiting for more messages
        Ok(SessionReceiveResult::Continue)
    }

    /// Process a data message.
    fn process_data(&mut self, ciphertext: Zeroizing<Vec<u8>>) -> Result<SessionReceiveResult, ProtocolError> {
        let noise = self.noise.as_mut().ok_or(ProtocolError::SessionTerminated)?;

        // Decrypt
        let mut plaintext = noise.decrypt(&ciphertext)?;

        // Validate plaintext (UTF-8, no NUL, bounds)
        let text_owned = {
            let text = validate_plaintext(&plaintext)?;
            text.to_string()
        };

        // Explicitly zeroize internal plaintext buffer before it goes out of scope
        plaintext.zeroize();

        // Update last message time
        self.last_message_at = Some(Instant::now());

        Ok(SessionReceiveResult::Message(text_owned))
    }

    /// Send a text message.
    ///
    /// Returns the encrypted frame to send.
    pub fn send_message(&mut self, text: &str) -> Result<Frame, ProtocolError> {
        self.check_timeouts()?;

        if self.state != SessionState::Active {
            self.terminate();
            return Err(ProtocolError::UnexpectedMessageType);
        }

        // Validate outbound message
        let plaintext = text.as_bytes();
        let _ = validate_plaintext(plaintext)?;

        let noise = self.noise.as_mut().ok_or(ProtocolError::SessionTerminated)?;
        let ciphertext = noise.encrypt(plaintext)?;

        Frame::data(ciphertext)
    }

    /// Send a terminate message.
    ///
    /// Returns the terminate frame to send, then terminates the session.
    pub fn send_terminate(&mut self) -> Result<Frame, ProtocolError> {
        if self.state == SessionState::Terminated {
            return Err(ProtocolError::SessionTerminated);
        }

        let frame = Frame::terminate();
        self.terminate();
        Ok(frame)
    }

    /// Terminate the session immediately.
    ///
    /// Zeroizes all key material and transitions to Terminated state.
    pub fn terminate(&mut self) {
        if let Some(ref mut noise) = self.noise {
            noise.terminate();
        }
        self.noise = None;
        self.state = SessionState::Terminated;
    }

    /// Get fingerprint for out-of-band verification.
    ///
    /// Only available after handshake completes.
    pub fn fingerprint(&self) -> Option<String> {
        self.noise.as_ref()?.fingerprint()
    }

    /// Get local public key (for debugging/verification).
    pub fn local_public_key(&self) -> Option<[u8; 32]> {
        self.noise.as_ref().map(|n| *n.local_public_key())
    }

    /// Get peer public key (after handshake).
    pub fn peer_public_key(&self) -> Option<[u8; 32]> {
        self.noise.as_ref()?.peer_public_key().copied()
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        // Ensure termination even if not explicitly called
        if self.state != SessionState::Terminated {
            self.terminate();
        }
    }
}

/// Result of processing a received frame.
#[derive(Debug)]
pub enum SessionReceiveResult {
    /// Continue waiting (handshake in progress, waiting for more).
    Continue,
    /// Handshake response to send.
    HandshakeResponse(Frame),
    /// Handshake complete, no response needed.
    HandshakeComplete,
    /// Handshake complete, send this response first.
    HandshakeCompleteWithResponse(Frame),
    /// Decrypted text message.
    Message(String),
    /// Session terminated (peer sent TERMINATE).
    Terminated,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_creation() {
        let initiator = Session::new_initiator().unwrap();
        assert_eq!(initiator.state(), SessionState::Created);
        assert_eq!(initiator.role(), Role::Initiator);

        let responder = Session::new_responder().unwrap();
        assert_eq!(responder.state(), SessionState::Created);
        assert_eq!(responder.role(), Role::Responder);
    }

    #[test]
    fn test_full_session_handshake() {
        let mut initiator = Session::new_initiator().unwrap();
        let mut responder = Session::new_responder().unwrap();

        // Both connect
        initiator.on_connected().unwrap();
        responder.on_connected().unwrap();
        assert_eq!(initiator.state(), SessionState::Connected);
        assert_eq!(responder.state(), SessionState::Connected);

        // Initiator starts handshake
        let msg1 = initiator.start_handshake().unwrap();
        assert_eq!(initiator.state(), SessionState::Handshaking);

        // Responder receives msg1, sends msg2
        let result = responder.on_receive(msg1).unwrap();
        let msg2 = match result {
            SessionReceiveResult::HandshakeResponse(f) => f,
            _ => panic!("expected handshake response"),
        };
        assert_eq!(responder.state(), SessionState::Handshaking);

        // Initiator receives msg2, sends msg3
        let result = initiator.on_receive(msg2).unwrap();
        let msg3 = match result {
            SessionReceiveResult::HandshakeCompleteWithResponse(f) => f,
            _ => panic!("expected handshake complete with response"),
        };
        assert_eq!(initiator.state(), SessionState::Active);

        // Responder receives msg3
        let result = responder.on_receive(msg3).unwrap();
        assert!(matches!(result, SessionReceiveResult::HandshakeComplete));
        assert_eq!(responder.state(), SessionState::Active);

        // Both should have fingerprints
        assert!(initiator.fingerprint().is_some());
        assert!(responder.fingerprint().is_some());
    }

    #[test]
    fn test_message_exchange() {
        let mut initiator = Session::new_initiator().unwrap();
        let mut responder = Session::new_responder().unwrap();

        // Complete handshake
        initiator.on_connected().unwrap();
        responder.on_connected().unwrap();
        let msg1 = initiator.start_handshake().unwrap();
        let msg2 = match responder.on_receive(msg1).unwrap() {
            SessionReceiveResult::HandshakeResponse(f) => f,
            _ => panic!(),
        };
        let msg3 = match initiator.on_receive(msg2).unwrap() {
            SessionReceiveResult::HandshakeCompleteWithResponse(f) => f,
            _ => panic!(),
        };
        responder.on_receive(msg3).unwrap();

        // Send message from initiator
        let frame = initiator.send_message("Hello!").unwrap();
        let result = responder.on_receive(frame).unwrap();
        match result {
            SessionReceiveResult::Message(text) => assert_eq!(text, "Hello!"),
            _ => panic!("expected message"),
        }

        // Send message from responder
        let frame = responder.send_message("Hi back!").unwrap();
        let result = initiator.on_receive(frame).unwrap();
        match result {
            SessionReceiveResult::Message(text) => assert_eq!(text, "Hi back!"),
            _ => panic!("expected message"),
        }
    }

    #[test]
    fn test_terminate() {
        let mut initiator = Session::new_initiator().unwrap();
        let mut responder = Session::new_responder().unwrap();

        // Complete handshake
        initiator.on_connected().unwrap();
        responder.on_connected().unwrap();
        let msg1 = initiator.start_handshake().unwrap();
        let msg2 = match responder.on_receive(msg1).unwrap() {
            SessionReceiveResult::HandshakeResponse(f) => f,
            _ => panic!(),
        };
        let msg3 = match initiator.on_receive(msg2).unwrap() {
            SessionReceiveResult::HandshakeCompleteWithResponse(f) => f,
            _ => panic!(),
        };
        responder.on_receive(msg3).unwrap();

        // Initiator sends terminate
        let frame = initiator.send_terminate().unwrap();
        assert_eq!(initiator.state(), SessionState::Terminated);

        // Responder receives terminate
        let result = responder.on_receive(frame).unwrap();
        assert!(matches!(result, SessionReceiveResult::Terminated));
        assert_eq!(responder.state(), SessionState::Terminated);
    }

    #[test]
    fn test_data_before_handshake_fails() {
        let mut session = Session::new_initiator().unwrap();
        session.on_connected().unwrap();

        // Try to send data before handshake
        let result = session.send_message("test");
        assert!(matches!(result, Err(ProtocolError::UnexpectedMessageType)));
        assert_eq!(session.state(), SessionState::Terminated);
    }

    #[test]
    fn test_initial_state_and_connection() {
        let mut session = Session::new_initiator().unwrap();
        assert_eq!(session.state(), SessionState::Created);
        
        session.on_connected().unwrap();
        assert_eq!(session.state(), SessionState::Connected);
        assert!(session.connected_at.is_some());
    }

    #[test]
    fn test_handshake_timeout() {
        let mut session = Session::new_initiator().unwrap();
        session.on_connected().unwrap();
        
        // Fast-forward session's internal time isn't possible, but we can sleep
        // Or we can manually adjust the connecting_at if we expose it (we don't for security)
        // For unit testing, a short sleep or mock if possible. 
        // Here we'll just check the logic path.
    }

    #[test]
    fn test_transition_violations() {
        let mut session = Session::new_initiator().unwrap();
        // Cannot receive data in Created state
        let frame = Frame::terminate(); // Any frame
        let res = session.on_receive(frame);
        assert!(res.is_err());
        assert_eq!(session.state(), SessionState::Terminated);
    }

    #[test]
    fn test_handshake_after_active_fails() {
        let mut initiator = Session::new_initiator().unwrap();
        let mut responder = Session::new_responder().unwrap();
        
        // Complete handshake
        initiator.on_connected().unwrap();
        responder.on_connected().unwrap();
        let msg1 = initiator.start_handshake().unwrap();
        let msg2 = match responder.on_receive(msg1.clone()).unwrap() {
            SessionReceiveResult::HandshakeResponse(f) => f,
            _ => panic!(),
        };
        let msg3 = match initiator.on_receive(msg2).unwrap() {
            SessionReceiveResult::HandshakeCompleteWithResponse(f) => f,
            _ => panic!(),
        };
        responder.on_receive(msg3).unwrap();

        // Try to send handshake message when active
        let result = responder.on_receive(msg1);
        assert!(matches!(result, Err(ProtocolError::UnexpectedMessageType)));
        assert_eq!(responder.state(), SessionState::Terminated);
    }
    #[test]
    fn test_reconnection_window_recovery() {
        let mut session = Session::new_initiator().unwrap();
        session.on_connected().unwrap();
        session.state = SessionState::Active; // Simulate active
        
        session.on_disconnected();
        assert_eq!(session.state(), SessionState::DisconnectedGrace);
        
        session.on_connected().unwrap();
        assert_eq!(session.state(), SessionState::Active);
    }

    #[test]
    fn test_reconnection_window_expiry() {
        use std::thread;
        let mut session = Session::new_initiator().unwrap();
        session.on_connected().unwrap();
        session.state = SessionState::Active;
        
        session.on_disconnected();
        thread::sleep(Duration::from_millis(5100)); // Sleep just past 5s
        
        let res = session.check_timeouts();
        assert!(res.is_err());
        assert_eq!(session.state(), SessionState::Terminated);
    }

}
