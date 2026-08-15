//! Native Protocol 2.1 secure-session state machine.

use crate::config::{Role, TransportConfig};
use crate::error::TransportError;
use crate::relay_v4::{RelayEventV4, RelayTransportV4};
use blindwire_core::entropy::random_array;
use blindwire_core::recovery::derive_continuity_secret;
use blindwire_core::{
    ApplicationEnvelope, Frame, MessageDeduplicator, MessageId, MessageType, NoiseSession,
};
use std::collections::{HashMap, VecDeque};
use std::time::Duration;

const HANDSHAKE_DEADLINE: Duration = Duration::from_secs(30);
const MAX_PLAINTEXT_SIZE: usize = 4000;

/// A user-visible event emitted by a Protocol 2.1 session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionEventV21 {
    /// Noise and recovery setup completed; the SAS can now be compared.
    VerificationReady,
    /// The peer sent an authenticated confirmation that its user accepted the SAS.
    PeerVerified,
    /// A new, deduplicated text message was received.
    TextReceived {
        /// Stable application message identifier.
        id: MessageId,
        /// Validated UTF-8 message body.
        text: String,
    },
    /// A pending local text message was acknowledged by the peer.
    MessageAcknowledged {
        /// Stable application message identifier.
        id: MessageId,
    },
    /// The transport disconnected and authenticated recovery may be attempted.
    Recovering,
    /// Authenticated recovery completed with fresh Noise keys.
    Recovered,
    /// The peer disconnected from the relay.
    PeerDisconnected,
    /// The room was irreversibly burned.
    RoomBurned,
}

/// A native Protocol 2.1 encrypted session.
///
/// Signaling controls remain outside Noise. Every application control and text
/// envelope is encrypted in a data frame.
pub struct SecureSessionV21 {
    config: TransportConfig,
    relay: RelayTransportV4,
    noise: NoiseSession,
    events: VecDeque<SessionEventV21>,
    continuity: Option<blindwire_core::recovery::ContinuitySecret>,
    recovery_capability: Option<[u8; 32]>,
    epoch: u64,
    local_verified: bool,
    peer_verified: bool,
    pending: HashMap<MessageId, ApplicationEnvelope>,
    deduplicator: MessageDeduplicator,
    terminated: bool,
}

impl std::fmt::Debug for SecureSessionV21 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SecureSessionV21")
            .field("role", &self.config.role)
            .field("epoch", &self.epoch)
            .field("local_verified", &self.local_verified)
            .field("peer_verified", &self.peer_verified)
            .field("terminated", &self.terminated)
            .finish_non_exhaustive()
    }
}

impl SecureSessionV21 {
    /// Join a signaling-v4 room and create a fresh Noise XX session.
    pub async fn connect_initial(
        config: TransportConfig,
    ) -> Result<(Self, Option<[u8; 32]>), TransportError> {
        crate::session::validate_signaling_url(&config)?;
        let noise = Self::new_noise(config.role)?;
        let (relay, token) = RelayTransportV4::connect_initial(&config).await?;
        Ok((
            Self {
                config,
                relay,
                noise,
                events: VecDeque::new(),
                continuity: None,
                recovery_capability: None,
                epoch: 0,
                local_verified: false,
                peer_verified: false,
                pending: HashMap::new(),
                deduplicator: MessageDeduplicator::new(),
                terminated: false,
            },
            token,
        ))
    }

    /// Complete Noise XX, relay confirmation, and encrypted recovery setup.
    pub async fn handshake(&mut self) -> Result<(), TransportError> {
        self.ensure_active_object()?;
        let result = match tokio::time::timeout(HANDSHAKE_DEADLINE, self.handshake_inner()).await {
            Ok(result) => result,
            Err(_) => Err(TransportError::Timeout),
        };
        if result.is_err() {
            self.terminate_local();
        }
        result
    }

    async fn handshake_inner(&mut self) -> Result<(), TransportError> {
        if self.config.role == Role::Initiator {
            self.wait_for_peer().await?;
            let first = self.noise.write_handshake()?;
            self.relay.send_frame(Frame::handshake(first)?).await?;
        }

        while !self.noise.is_handshake_complete() {
            let frame = self.recv_handshake_frame().await?;
            if frame.msg_type() != MessageType::Handshake {
                return Err(TransportError::HandshakeFailed);
            }
            self.noise.read_handshake(frame.payload())?;
            if !self.noise.is_handshake_complete() && self.noise.is_my_turn()? {
                let response = self.noise.write_handshake()?;
                self.relay.send_frame(Frame::handshake(response)?).await?;
            }
        }

        self.relay.send_handshake_complete().await?;
        loop {
            match self.relay.recv_event().await? {
                RelayEventV4::HandshakeConfirmed => break,
                RelayEventV4::PeerJoined => {}
                RelayEventV4::PeerQuit => return Err(TransportError::PeerDisconnected),
                RelayEventV4::Expired | RelayEventV4::RoomBurned => {
                    return Err(TransportError::SessionTerminated)
                }
                event => return Err(Self::unexpected_relay_event(event)),
            }
        }

        self.establish_initial_continuity().await?;
        self.events.push_back(SessionEventV21::VerificationReady);
        Ok(())
    }

    async fn establish_initial_continuity(&mut self) -> Result<(), TransportError> {
        let local_contribution = random_array::<32>()?;
        self.send_envelope(&ApplicationEnvelope::RecoveryContribution(
            local_contribution,
        ))
        .await?;

        let peer_contribution = match self.recv_envelope().await? {
            ApplicationEnvelope::RecoveryContribution(contribution) => contribution,
            _ => return Err(TransportError::UnexpectedApplicationEnvelope),
        };
        let (initiator, responder) = match self.config.role {
            Role::Initiator => (&local_contribution, &peer_contribution),
            Role::Responder => (&peer_contribution, &local_contribution),
        };
        self.continuity = Some(derive_continuity_secret(
            &self.config.session_id,
            initiator,
            responder,
        )?);

        let capability = random_array::<32>()?;
        self.relay.register_recovery(capability).await?;
        match self.relay.recv_event().await? {
            RelayEventV4::RecoveryRegistered => {
                self.recovery_capability = Some(capability);
                Ok(())
            }
            event => Err(Self::unexpected_relay_event(event)),
        }
    }

    /// Confirm that the local user accepted the displayed SAS.
    pub async fn confirm_user_verified(&mut self) -> Result<(), TransportError> {
        self.ensure_active_object()?;
        let result = self.confirm_user_verified_inner().await;
        if result.is_err() {
            self.terminate_local();
        }
        result
    }

    async fn confirm_user_verified_inner(&mut self) -> Result<(), TransportError> {
        if !self.local_verified {
            self.send_envelope(&ApplicationEnvelope::UserVerified)
                .await?;
            self.local_verified = true;
        }
        Ok(())
    }

    /// Send an encrypted text envelope after both users verified the SAS.
    pub async fn send_text(&mut self, text: &str) -> Result<MessageId, TransportError> {
        self.ensure_active_object()?;
        let result = self.send_text_inner(text).await;
        if result.is_err() {
            self.terminate_local();
        }
        result
    }

    async fn send_text_inner(&mut self, text: &str) -> Result<MessageId, TransportError> {
        if !self.local_verified || !self.peer_verified {
            return Err(TransportError::VerificationRequired);
        }
        if text.contains('\0') {
            return Err(TransportError::ContainsNul);
        }
        if text.len() > MAX_PLAINTEXT_SIZE {
            return Err(TransportError::MessageTooLong);
        }

        let id = MessageId::generate()?;
        let envelope = ApplicationEnvelope::Text {
            id,
            body: text.to_owned(),
        };
        self.send_envelope(&envelope).await?;
        self.pending.insert(id, envelope);
        Ok(id)
    }

    /// Receive the next authenticated user-visible session event.
    pub async fn recv_event(&mut self) -> Result<SessionEventV21, TransportError> {
        self.ensure_active_object()?;
        if let Some(event) = self.events.pop_front() {
            return Ok(event);
        }

        let result = self.recv_event_inner().await;
        match result {
            Ok(event) => Ok(event),
            Err(TransportError::PeerDisconnected) => {
                self.terminate_local();
                Ok(SessionEventV21::PeerDisconnected)
            }
            Err(TransportError::RoomBurned) => {
                self.terminate_local();
                Ok(SessionEventV21::RoomBurned)
            }
            Err(error) => {
                self.terminate_local();
                Err(error)
            }
        }
    }

    /// Encrypt a burn control, burn the relay room, and terminate locally.
    pub async fn burn(mut self) -> Result<(), TransportError> {
        self.ensure_active_object()?;
        let encrypted = self.send_envelope(&ApplicationEnvelope::BurnRoom).await;
        let relay = self.relay.burn().await;
        self.terminate_local();
        match encrypted {
            Err(error) => Err(error),
            Ok(()) => relay,
        }
    }

    async fn recv_event_inner(&mut self) -> Result<SessionEventV21, TransportError> {
        loop {
            let envelope = self.recv_envelope().await?;
            match envelope {
                ApplicationEnvelope::UserVerified => {
                    self.peer_verified = true;
                    return Ok(SessionEventV21::PeerVerified);
                }
                ApplicationEnvelope::Text { id, body } => {
                    if !self.local_verified || !self.peer_verified {
                        return Err(TransportError::VerificationRequired);
                    }
                    let first_observation = self.deduplicator.observe(id);
                    self.send_envelope(&ApplicationEnvelope::Ack { id }).await?;
                    if first_observation {
                        return Ok(SessionEventV21::TextReceived { id, text: body });
                    }
                }
                ApplicationEnvelope::Ack { id } => {
                    if !self.local_verified || !self.peer_verified {
                        return Err(TransportError::VerificationRequired);
                    }
                    if self.pending.remove(&id).is_some() {
                        return Ok(SessionEventV21::MessageAcknowledged { id });
                    }
                }
                ApplicationEnvelope::BurnRoom => {
                    return Err(TransportError::RoomBurned);
                }
                ApplicationEnvelope::RecoveryContribution(_)
                | ApplicationEnvelope::ResumeProof { .. } => {
                    return Err(TransportError::UnexpectedApplicationEnvelope);
                }
            }
        }
    }

    async fn send_envelope(
        &mut self,
        envelope: &ApplicationEnvelope,
    ) -> Result<(), TransportError> {
        let plaintext = envelope.encode()?;
        let ciphertext = self.noise.encrypt(&plaintext)?;
        self.relay.send_frame(Frame::data(ciphertext)?).await
    }

    async fn recv_envelope(&mut self) -> Result<ApplicationEnvelope, TransportError> {
        loop {
            match self.relay.recv_event().await? {
                RelayEventV4::Frame(frame) => {
                    if frame.msg_type() == MessageType::Terminate {
                        return Err(TransportError::SessionTerminated);
                    }
                    if frame.msg_type() != MessageType::Data {
                        return Err(TransportError::UnexpectedApplicationEnvelope);
                    }
                    let plaintext = self.noise.decrypt(frame.payload())?;
                    return ApplicationEnvelope::decode(&plaintext).map_err(Into::into);
                }
                RelayEventV4::PeerJoined => {}
                RelayEventV4::PeerQuit => return Err(TransportError::PeerDisconnected),
                RelayEventV4::RoomBurned => return Err(TransportError::RoomBurned),
                RelayEventV4::Expired => return Err(TransportError::SessionTerminated),
                event => return Err(Self::unexpected_relay_event(event)),
            }
        }
    }

    async fn wait_for_peer(&mut self) -> Result<(), TransportError> {
        match self.relay.recv_event().await? {
            RelayEventV4::PeerJoined => Ok(()),
            RelayEventV4::PeerQuit => Err(TransportError::PeerDisconnected),
            RelayEventV4::Expired | RelayEventV4::RoomBurned => {
                Err(TransportError::SessionTerminated)
            }
            event => Err(Self::unexpected_relay_event(event)),
        }
    }

    async fn recv_handshake_frame(&mut self) -> Result<Frame, TransportError> {
        loop {
            match self.relay.recv_event().await? {
                RelayEventV4::Frame(frame) => return Ok(frame),
                RelayEventV4::PeerJoined => {}
                RelayEventV4::PeerQuit => return Err(TransportError::PeerDisconnected),
                RelayEventV4::Expired | RelayEventV4::RoomBurned => {
                    return Err(TransportError::SessionTerminated)
                }
                event => return Err(Self::unexpected_relay_event(event)),
            }
        }
    }

    fn new_noise(role: Role) -> Result<NoiseSession, TransportError> {
        match role {
            Role::Initiator => NoiseSession::new_initiator().map_err(Into::into),
            Role::Responder => NoiseSession::new_responder().map_err(Into::into),
        }
    }

    fn unexpected_relay_event(event: RelayEventV4) -> TransportError {
        match event {
            RelayEventV4::Error(code) => match code {
                0x06 => TransportError::VersionMismatch,
                0x07 => TransportError::RateLimitExceeded,
                0x09 => TransportError::SessionTerminated,
                other => TransportError::UnexpectedResponse(other),
            },
            RelayEventV4::Frame(_) => TransportError::UnexpectedResponse(0x01),
            RelayEventV4::PeerJoined => TransportError::UnexpectedResponse(0x02),
            RelayEventV4::PeerQuit => TransportError::UnexpectedResponse(0x03),
            RelayEventV4::Expired => TransportError::UnexpectedResponse(0x04),
            RelayEventV4::HandshakeConfirmed => TransportError::UnexpectedResponse(0x07),
            RelayEventV4::RecoveryRegistered => TransportError::UnexpectedResponse(0x08),
            RelayEventV4::PeerResuming { .. } => TransportError::UnexpectedResponse(0x09),
            RelayEventV4::ResumeReady { .. } => TransportError::UnexpectedResponse(0x0a),
            RelayEventV4::Token(_) => TransportError::UnexpectedResponse(0x06),
            RelayEventV4::RoomBurned => TransportError::RoomBurned,
        }
    }

    fn ensure_active_object(&self) -> Result<(), TransportError> {
        if self.terminated || self.noise.is_terminated() {
            Err(TransportError::SessionTerminated)
        } else {
            Ok(())
        }
    }

    fn terminate_local(&mut self) {
        if !self.terminated {
            self.noise.terminate();
            self.continuity = None;
            self.recovery_capability = None;
            self.pending.clear();
            self.terminated = true;
        }
    }
}

impl Drop for SecureSessionV21 {
    fn drop(&mut self) {
        self.terminate_local();
    }
}
