//! Native Protocol 2.1 secure-session state machine.

use crate::config::{Role, TransportConfig};
use crate::error::TransportError;
use crate::relay_v4::{RelayEventV4, RelayTransportV4};
use blindwire_core::entropy::random_array;
use blindwire_core::noise::Role as NoiseRole;
use blindwire_core::recovery::{
    compute_resume_proof, derive_continuity_secret, ratchet_continuity_secret, verify_resume_proof,
    ContinuitySecret,
};
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

/// Non-cloneable authenticated state used for one recovery attempt.
pub struct RecoverySnapshotV21 {
    continuity: ContinuitySecret,
    capability: [u8; 32],
    session_id: [u8; 32],
    role: Role,
    epoch: u64,
    local_verified: bool,
    peer_verified: bool,
    pending: HashMap<MessageId, ApplicationEnvelope>,
    deduplicator: MessageDeduplicator,
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
    continuity: Option<ContinuitySecret>,
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

    /// Consume the active continuity state into a one-use recovery snapshot.
    pub fn recovery_snapshot(&mut self) -> Result<RecoverySnapshotV21, TransportError> {
        self.ensure_active_object()?;
        let continuity = self
            .continuity
            .take()
            .ok_or(TransportError::RecoveryUnavailable)?;
        let capability = self
            .recovery_capability
            .take()
            .ok_or(TransportError::RecoveryUnavailable)?;
        self.noise.terminate();
        self.relay.detach();
        self.terminated = true;
        Ok(RecoverySnapshotV21 {
            continuity,
            capability,
            session_id: self.config.session_id,
            role: self.config.role,
            epoch: self.epoch,
            local_verified: self.local_verified,
            peer_verified: self.peer_verified,
            pending: std::mem::take(&mut self.pending),
            deduplicator: std::mem::take(&mut self.deduplicator),
        })
    }

    /// Resume a session from a one-use authenticated recovery snapshot.
    pub async fn resume(
        config: TransportConfig,
        snapshot: RecoverySnapshotV21,
    ) -> Result<Self, TransportError> {
        crate::session::validate_signaling_url(&config)?;
        if config.role != snapshot.role || config.session_id != snapshot.session_id {
            return Err(TransportError::RecoveryUnavailable);
        }
        let next_epoch = snapshot
            .epoch
            .checked_add(1)
            .ok_or(TransportError::StaleEpoch)?;
        let relay =
            RelayTransportV4::connect_resume(&config, snapshot.capability, snapshot.epoch).await?;
        let mut session = Self {
            config,
            relay,
            noise: Self::new_noise(snapshot.role)?,
            events: VecDeque::new(),
            continuity: Some(snapshot.continuity),
            recovery_capability: None,
            epoch: next_epoch,
            local_verified: false,
            peer_verified: false,
            pending: snapshot.pending,
            deduplicator: snapshot.deduplicator,
            terminated: false,
        };
        let _previous_verification = (snapshot.local_verified, snapshot.peer_verified);

        let result = session.resume_inner(next_epoch).await;
        if let Err(error) = result {
            session.terminate_local();
            return Err(error);
        }
        session.events.push_back(SessionEventV21::Recovering);
        session.events.push_back(SessionEventV21::Recovered);
        Ok(session)
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
            match self.relay.recv_event().await? {
                RelayEventV4::Frame(frame) => {
                    let envelope = self.decrypt_application_frame(frame)?;
                    if let Some(event) = self.process_application_envelope(envelope).await? {
                        return Ok(event);
                    }
                }
                RelayEventV4::PeerResuming { epoch } => {
                    self.recover_as_connected_peer(epoch).await?;
                    self.events.push_back(SessionEventV21::Recovered);
                    return Ok(SessionEventV21::Recovering);
                }
                RelayEventV4::PeerJoined => {}
                RelayEventV4::PeerQuit => return Err(TransportError::PeerDisconnected),
                RelayEventV4::RoomBurned => return Err(TransportError::RoomBurned),
                RelayEventV4::Expired => return Err(TransportError::SessionTerminated),
                event => return Err(Self::unexpected_relay_event(event)),
            }
        }
    }

    async fn process_application_envelope(
        &mut self,
        envelope: ApplicationEnvelope,
    ) -> Result<Option<SessionEventV21>, TransportError> {
        match envelope {
            ApplicationEnvelope::UserVerified => {
                self.peer_verified = true;
                Ok(Some(SessionEventV21::PeerVerified))
            }
            ApplicationEnvelope::Text { id, body } => {
                if !self.local_verified || !self.peer_verified {
                    return Err(TransportError::VerificationRequired);
                }
                let first_observation = self.deduplicator.observe(id);
                self.send_envelope(&ApplicationEnvelope::Ack { id }).await?;
                if first_observation {
                    Ok(Some(SessionEventV21::TextReceived { id, text: body }))
                } else {
                    Ok(None)
                }
            }
            ApplicationEnvelope::Ack { id } => {
                if !self.local_verified || !self.peer_verified {
                    return Err(TransportError::VerificationRequired);
                }
                if self.pending.remove(&id).is_some() {
                    Ok(Some(SessionEventV21::MessageAcknowledged { id }))
                } else {
                    Ok(None)
                }
            }
            ApplicationEnvelope::BurnRoom => Err(TransportError::RoomBurned),
            ApplicationEnvelope::RecoveryContribution(_)
            | ApplicationEnvelope::ResumeProof { .. } => {
                Err(TransportError::UnexpectedApplicationEnvelope)
            }
        }
    }

    async fn resume_inner(&mut self, epoch: u64) -> Result<(), TransportError> {
        let result = tokio::time::timeout(HANDSHAKE_DEADLINE, self.perform_fresh_noise_handshake())
            .await
            .map_err(|_| TransportError::Timeout)?;
        result?;
        self.establish_resumed_continuity(epoch).await
    }

    async fn recover_as_connected_peer(&mut self, epoch: u64) -> Result<(), TransportError> {
        let expected_epoch = self
            .epoch
            .checked_add(1)
            .ok_or(TransportError::StaleEpoch)?;
        if epoch != expected_epoch {
            return Err(TransportError::StaleEpoch);
        }
        self.noise.terminate();
        self.noise = Self::new_noise(self.config.role)?;
        self.local_verified = false;
        self.peer_verified = false;
        self.recovery_capability = None;
        self.epoch = epoch;
        self.resume_inner(epoch).await
    }

    async fn perform_fresh_noise_handshake(&mut self) -> Result<(), TransportError> {
        if self.config.role == Role::Initiator {
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
        match self.relay.recv_event().await? {
            RelayEventV4::HandshakeConfirmed => Ok(()),
            RelayEventV4::PeerQuit => Err(TransportError::PeerDisconnected),
            RelayEventV4::Expired | RelayEventV4::RoomBurned => {
                Err(TransportError::SessionTerminated)
            }
            event => Err(Self::unexpected_relay_event(event)),
        }
    }

    async fn establish_resumed_continuity(&mut self, epoch: u64) -> Result<(), TransportError> {
        let fingerprint = self
            .noise
            .fingerprint_bytes()
            .ok_or(TransportError::HandshakeFailed)?;
        let local_role = Self::noise_role_for(self.config.role);
        let peer_role = Self::noise_role_for(match self.config.role {
            Role::Initiator => Role::Responder,
            Role::Responder => Role::Initiator,
        });
        let local_mac = {
            let continuity = self
                .continuity
                .as_ref()
                .ok_or(TransportError::RecoveryUnavailable)?;
            compute_resume_proof(
                continuity,
                &self.config.session_id,
                local_role,
                epoch,
                &fingerprint,
            )
        };
        self.send_envelope(&ApplicationEnvelope::ResumeProof {
            epoch,
            mac: local_mac,
        })
        .await?;

        match self.recv_envelope().await? {
            ApplicationEnvelope::ResumeProof {
                epoch: peer_epoch,
                mac,
            } if peer_epoch == epoch => {
                let continuity = self
                    .continuity
                    .as_ref()
                    .ok_or(TransportError::RecoveryUnavailable)?;
                verify_resume_proof(
                    continuity,
                    &self.config.session_id,
                    peer_role,
                    epoch,
                    &fingerprint,
                    &mac,
                )?;
            }
            ApplicationEnvelope::ResumeProof { .. } => return Err(TransportError::StaleEpoch),
            _ => return Err(TransportError::UnexpectedApplicationEnvelope),
        }

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
        let previous = self
            .continuity
            .take()
            .ok_or(TransportError::RecoveryUnavailable)?;
        let next = ratchet_continuity_secret(
            previous,
            &self.config.session_id,
            epoch,
            initiator,
            responder,
        )?;
        self.continuity = Some(next);

        let capability = random_array::<32>()?;
        self.relay.register_recovery(capability).await?;
        match self.relay.recv_event().await? {
            RelayEventV4::RecoveryRegistered => {
                self.recovery_capability = Some(capability);
                self.local_verified = false;
                self.peer_verified = false;
                Ok(())
            }
            event => Err(Self::unexpected_relay_event(event)),
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
                    return self.decrypt_application_frame(frame);
                }
                RelayEventV4::PeerJoined => {}
                RelayEventV4::PeerQuit => return Err(TransportError::PeerDisconnected),
                RelayEventV4::RoomBurned => return Err(TransportError::RoomBurned),
                RelayEventV4::Expired => return Err(TransportError::SessionTerminated),
                RelayEventV4::PeerResuming { .. } => {
                    return Err(TransportError::UnexpectedResponse(0x09))
                }
                event => return Err(Self::unexpected_relay_event(event)),
            }
        }
    }

    fn decrypt_application_frame(
        &mut self,
        frame: Frame,
    ) -> Result<ApplicationEnvelope, TransportError> {
        if frame.msg_type() == MessageType::Terminate {
            return Err(TransportError::SessionTerminated);
        }
        if frame.msg_type() != MessageType::Data {
            return Err(TransportError::UnexpectedApplicationEnvelope);
        }
        let plaintext = self.noise.decrypt(frame.payload())?;
        ApplicationEnvelope::decode(&plaintext).map_err(Into::into)
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

    fn noise_role_for(role: Role) -> NoiseRole {
        match role {
            Role::Initiator => NoiseRole::Initiator,
            Role::Responder => NoiseRole::Responder,
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
