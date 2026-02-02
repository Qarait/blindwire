//! Noise_XX handshake wrapper.
//!
//! This module wraps the `snow` library to provide a minimal Noise_XX interface.
//!
//! # Security Properties
//!
//! - Static keys are generated fresh per session (session-scoped, not persisted)
//! - All key material implements Zeroize and is dropped explicitly
//! - Any handshake error is terminal
//! - No fallback patterns, no negotiation

use snow::{Builder, HandshakeState, TransportState};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::ProtocolError;
use crate::frame::MAX_WIRE_LENGTH;

/// Noise protocol pattern identifier.
/// Noise_XX with Curve25519, ChaChaPoly, and BLAKE2s.
const NOISE_PATTERN: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";

/// Maximum Noise message size (same as wire limit).
const MAX_NOISE_MSG_SIZE: usize = MAX_WIRE_LENGTH;

/// Role in the handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Session creator. Sends first message.
    Initiator,
    /// Session joiner. Receives first message.
    Responder,
}

/// Session-scoped static keypair.
///
/// Generated fresh for each session. Never persisted. Zeroized on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SessionKeypair {
    secret: [u8; 32],
    public: [u8; 32],
}

impl SessionKeypair {
    /// Generate a new random keypair.
    ///
    /// Uses snow's internal CSPRNG (OS-provided randomness).
    pub fn generate() -> Result<Self, ProtocolError> {
        let builder = Builder::new(NOISE_PATTERN.parse().map_err(|_| ProtocolError::InternalError)?);
        let keypair = builder.generate_keypair().map_err(|_| ProtocolError::InternalError)?;
        
        let mut secret = [0u8; 32];
        let mut public = [0u8; 32];
        
        secret.copy_from_slice(&keypair.private);
        public.copy_from_slice(&keypair.public);
        
        Ok(Self { secret, public })
    }

    /// Get the public key (for fingerprint verification).
    pub fn public_key(&self) -> &[u8; 32] {
        &self.public
    }
}

/// Noise session state.
///
/// Wraps snow's state machine and ensures proper zeroization.
pub struct NoiseSession {
    state: NoiseState,
    role: Role,
    /// Our static keypair (session-scoped).
    keypair: SessionKeypair,
    /// Peer's static public key (available after handshake completes).
    peer_public: Option<[u8; 32]>,
}

enum NoiseState {
    /// Handshake in progress.
    Handshake(Box<HandshakeState>),
    /// Transport established.
    Transport(Box<TransportState>),
    /// Session terminated (state consumed).
    Terminated,
}

impl NoiseSession {
    /// Create a new Noise session as initiator.
    pub fn new_initiator() -> Result<Self, ProtocolError> {
        let keypair = SessionKeypair::generate()?;
        
        let builder = Builder::new(NOISE_PATTERN.parse().map_err(|_| ProtocolError::InternalError)?)
            .local_private_key(&keypair.secret)
            .build_initiator()
            .map_err(|_| ProtocolError::InternalError)?;

        Ok(Self {
            state: NoiseState::Handshake(Box::new(builder)),
            role: Role::Initiator,
            keypair,
            peer_public: None,
        })
    }

    /// Create a new Noise session as responder.
    pub fn new_responder() -> Result<Self, ProtocolError> {
        let keypair = SessionKeypair::generate()?;
        
        let builder = Builder::new(NOISE_PATTERN.parse().map_err(|_| ProtocolError::InternalError)?)
            .local_private_key(&keypair.secret)
            .build_responder()
            .map_err(|_| ProtocolError::InternalError)?;

        Ok(Self {
            state: NoiseState::Handshake(Box::new(builder)),
            role: Role::Responder,
            keypair,
            peer_public: None,
        })
    }

    /// Get our role.
    pub fn role(&self) -> Role {
        self.role
    }

    /// Check if handshake is complete.
    pub fn is_handshake_complete(&self) -> bool {
        matches!(self.state, NoiseState::Transport(_))
    }

    /// Check if session is terminated.
    pub fn is_terminated(&self) -> bool {
        matches!(self.state, NoiseState::Terminated)
    }

    /// Get our static public key (for fingerprint display).
    pub fn local_public_key(&self) -> &[u8; 32] {
        self.keypair.public_key()
    }

    /// Get peer's static public key (available after handshake).
    pub fn peer_public_key(&self) -> Option<&[u8; 32]> {
        self.peer_public.as_ref()
    }

    /// Check if it's our turn to send a handshake message.
    pub fn is_my_turn(&self) -> Result<bool, ProtocolError> {
        match &self.state {
            NoiseState::Handshake(hs) => Ok(hs.is_my_turn()),
            NoiseState::Transport(_) => Ok(true), // Can always send data
            NoiseState::Terminated => Err(ProtocolError::SessionTerminated),
        }
    }

    /// Write (send) a handshake message.
    ///
    /// Returns the handshake message bytes to send to peer.
    ///
    /// # Errors
    ///
    /// Returns error if not in handshake state or not our turn.
    pub fn write_handshake(&mut self) -> Result<Vec<u8>, ProtocolError> {
        let hs = match &mut self.state {
            NoiseState::Handshake(hs) => hs,
            NoiseState::Transport(_) => return Err(ProtocolError::UnexpectedMessageType),
            NoiseState::Terminated => return Err(ProtocolError::SessionTerminated),
        };

        if !hs.is_my_turn() {
            return Err(ProtocolError::UnexpectedMessageType);
        }

        let mut buf = vec![0u8; MAX_NOISE_MSG_SIZE];
        let len = hs.write_message(&[], &mut buf).map_err(|_| ProtocolError::HandshakeFailed)?;
        buf.truncate(len);

        // Check if handshake is complete after this message
        self.maybe_transition_to_transport()?;

        Ok(buf)
    }

    /// Read (receive) a handshake message from peer.
    ///
    /// # Errors
    ///
    /// Returns error if not in handshake state, is our turn, or message is invalid.
    pub fn read_handshake(&mut self, message: &[u8]) -> Result<(), ProtocolError> {
        let hs = match &mut self.state {
            NoiseState::Handshake(hs) => hs,
            NoiseState::Transport(_) => return Err(ProtocolError::UnexpectedMessageType),
            NoiseState::Terminated => return Err(ProtocolError::SessionTerminated),
        };

        if hs.is_my_turn() {
            return Err(ProtocolError::UnexpectedMessageType);
        }

        let mut buf = vec![0u8; MAX_NOISE_MSG_SIZE];
        let _len = hs.read_message(message, &mut buf).map_err(|_| ProtocolError::HandshakeFailed)?;

        // Check if handshake is complete after this message
        self.maybe_transition_to_transport()?;

        Ok(())
    }

    /// Transition from handshake to transport state if handshake is complete.
    fn maybe_transition_to_transport(&mut self) -> Result<(), ProtocolError> {
        // Check if handshake is complete
        let is_finished = match &self.state {
            NoiseState::Handshake(hs) => hs.is_handshake_finished(),
            _ => return Ok(()),
        };

        if !is_finished {
            return Ok(());
        }

        // Extract handshake state and convert to transport
        let old_state = std::mem::replace(&mut self.state, NoiseState::Terminated);
        let hs = match old_state {
            NoiseState::Handshake(hs) => hs,
            _ => return Err(ProtocolError::InternalError),
        };

        // Get peer's static public key before converting
        let peer_key = hs.get_remote_static();
        if let Some(key) = peer_key {
            let mut peer_pub = [0u8; 32];
            peer_pub.copy_from_slice(key);
            self.peer_public = Some(peer_pub);
        }

        // Convert to transport state
        let transport = hs.into_transport_mode().map_err(|_| ProtocolError::HandshakeFailed)?;
        self.state = NoiseState::Transport(Box::new(transport));

        Ok(())
    }

    /// Encrypt a message for sending.
    ///
    /// # Errors
    ///
    /// Returns error if not in transport state or encryption fails.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, ProtocolError> {
        let transport = match &mut self.state {
            NoiseState::Transport(t) => t,
            NoiseState::Handshake(_) => return Err(ProtocolError::UnexpectedMessageType),
            NoiseState::Terminated => return Err(ProtocolError::SessionTerminated),
        };

        // Noise adds 16 bytes for the authentication tag
        let mut buf = vec![0u8; plaintext.len() + 16];
        let len = transport.write_message(plaintext, &mut buf).map_err(|_| ProtocolError::DecryptionFailed)?;
        buf.truncate(len);

        Ok(buf)
    }

    /// Decrypt a message from peer.
    ///
    /// # Errors
    ///
    /// Returns error if not in transport state, decryption fails, or authentication fails.
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, ProtocolError> {
        let transport = match &mut self.state {
            NoiseState::Transport(t) => t,
            NoiseState::Handshake(_) => return Err(ProtocolError::UnexpectedMessageType),
            NoiseState::Terminated => return Err(ProtocolError::SessionTerminated),
        };

        // Ciphertext must be at least 16 bytes (authentication tag)
        if ciphertext.len() < 16 {
            return Err(ProtocolError::DecryptionFailed);
        }

        let mut buf = vec![0u8; ciphertext.len()];
        let len = transport.read_message(ciphertext, &mut buf).map_err(|_| ProtocolError::DecryptionFailed)?;
        buf.truncate(len);

        Ok(buf)
    }

    /// Terminate the session and zeroize all key material.
    ///
    /// After calling this, the session cannot be used.
    pub fn terminate(&mut self) {
        // Replace state with Terminated, dropping old state
        self.state = NoiseState::Terminated;
        
        // keypair will be zeroized when self is dropped (ZeroizeOnDrop)
        // peer_public is just a public key, but we clear it anyway
        if let Some(ref mut key) = self.peer_public {
            key.zeroize();
        }
        self.peer_public = None;
    }

    /// Compute session fingerprint for out-of-band verification.
    ///
    /// Returns first 8 bytes of SHA256(initiator_pub || responder_pub) as hex string.
    /// Only available after handshake completes.
    pub fn fingerprint(&self) -> Option<String> {
        use sha2::{Digest, Sha256};
        
        let peer_pub = self.peer_public.as_ref()?;
        
        let mut hasher = Sha256::new();
        if self.role == Role::Initiator {
            hasher.update(&self.keypair.public);
            hasher.update(peer_pub);
        } else {
            hasher.update(peer_pub);
            hasher.update(&self.keypair.public);
        }
        let result = hasher.finalize();
        
        Some(hex::encode(&result[..8])) // 16 hex chars
    }
}

impl Drop for NoiseSession {
    fn drop(&mut self) {
        // Ensure termination even if not explicitly called
        if !self.is_terminated() {
            self.terminate();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let kp1 = SessionKeypair::generate().unwrap();
        let kp2 = SessionKeypair::generate().unwrap();
        
        // Each keypair should be unique
        assert_ne!(kp1.public, kp2.public);
    }

    #[test]
    fn test_full_handshake() {
        let mut initiator = NoiseSession::new_initiator().unwrap();
        let mut responder = NoiseSession::new_responder().unwrap();

        // Initiator sends msg 1
        assert!(initiator.is_my_turn().unwrap());
        let msg1 = initiator.write_handshake().unwrap();

        // Responder receives msg 1, sends msg 2
        assert!(!responder.is_my_turn().unwrap());
        responder.read_handshake(&msg1).unwrap();
        assert!(responder.is_my_turn().unwrap());
        let msg2 = responder.write_handshake().unwrap();

        // Initiator receives msg 2, sends msg 3
        assert!(!initiator.is_my_turn().unwrap());
        initiator.read_handshake(&msg2).unwrap();
        assert!(initiator.is_my_turn().unwrap());
        let msg3 = initiator.write_handshake().unwrap();

        // Responder receives msg 3, handshake complete
        responder.read_handshake(&msg3).unwrap();

        // Both should be in transport mode
        assert!(initiator.is_handshake_complete());
        assert!(responder.is_handshake_complete());

        // Both should have peer's public key
        assert!(initiator.peer_public_key().is_some());
        assert!(responder.peer_public_key().is_some());

        // Peer public keys should match
        assert_eq!(
            initiator.peer_public_key().unwrap(),
            responder.local_public_key()
        );
        assert_eq!(
            responder.peer_public_key().unwrap(),
            initiator.local_public_key()
        );
    }

    #[test]
    fn test_encrypt_decrypt() {
        let mut initiator = NoiseSession::new_initiator().unwrap();
        let mut responder = NoiseSession::new_responder().unwrap();

        // Complete handshake
        let msg1 = initiator.write_handshake().unwrap();
        responder.read_handshake(&msg1).unwrap();
        let msg2 = responder.write_handshake().unwrap();
        initiator.read_handshake(&msg2).unwrap();
        let msg3 = initiator.write_handshake().unwrap();
        responder.read_handshake(&msg3).unwrap();

        // Send message from initiator to responder
        let plaintext = b"Hello, secure world!";
        let ciphertext = initiator.encrypt(plaintext).unwrap();
        let decrypted = responder.decrypt(&ciphertext).unwrap();
        assert_eq!(&decrypted, plaintext);

        // Send message from responder to initiator
        let plaintext2 = b"Hello back!";
        let ciphertext2 = responder.encrypt(plaintext2).unwrap();
        let decrypted2 = initiator.decrypt(&ciphertext2).unwrap();
        assert_eq!(&decrypted2, plaintext2);
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let mut initiator = NoiseSession::new_initiator().unwrap();
        let mut responder = NoiseSession::new_responder().unwrap();

        // Complete handshake
        let msg1 = initiator.write_handshake().unwrap();
        responder.read_handshake(&msg1).unwrap();
        let msg2 = responder.write_handshake().unwrap();
        initiator.read_handshake(&msg2).unwrap();
        let msg3 = initiator.write_handshake().unwrap();
        responder.read_handshake(&msg3).unwrap();

        // Encrypt a message
        let plaintext = b"Secret message";
        let mut ciphertext = initiator.encrypt(plaintext).unwrap();

        // Tamper with ciphertext
        ciphertext[0] ^= 0xFF;

        // Decryption should fail
        assert_eq!(
            responder.decrypt(&ciphertext),
            Err(ProtocolError::DecryptionFailed)
        );
    }

    #[test]
    fn test_terminate_prevents_use() {
        let mut session = NoiseSession::new_initiator().unwrap();
        session.terminate();
        
        assert!(session.is_terminated());
        assert_eq!(session.is_my_turn(), Err(ProtocolError::SessionTerminated));
        assert_eq!(session.write_handshake(), Err(ProtocolError::SessionTerminated));
    }
}
