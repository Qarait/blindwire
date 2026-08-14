use std::collections::{HashMap, VecDeque};

use blindwire_core::{
    application::{ApplicationEnvelope, MessageDeduplicator, MessageId},
    entropy::random_array,
    frame::{Frame, MessageType, LENGTH_PREFIX_SIZE},
    noise::{NoiseSession, Role},
    recovery::{
        compute_resume_proof, derive_continuity_secret, ratchet_continuity_secret,
        verify_resume_proof, ContinuitySecret,
    },
    sas, ProtocolError,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

const ROLE_INITIATOR: u8 = b'i';
const ROLE_RESPONDER: u8 = b'r';
const SNAPSHOT_MAGIC: &[u8; 4] = b"BWRS";
const SNAPSHOT_VERSION: u8 = 1;
const SNAPSHOT_DIGEST_LENGTH: usize = 32;
const DEDUPLICATION_CAPACITY: usize = 256;
const MAX_SNAPSHOT_LENGTH: usize = 1_048_576;

#[derive(Serialize)]
struct CallResult {
    events: Vec<PublicEvent>,
    #[serde(skip_serializing_if = "Option::is_none")]
    message_id: Option<Vec<u8>>,
}

#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum PublicEvent {
    Outbound {
        frame: Vec<u8>,
    },
    Verification {
        emojis: Vec<String>,
        numeric: [u16; 7],
    },
    PeerVerified,
    Text {
        id: Vec<u8>,
        text: String,
    },
    Acknowledgement {
        id: Vec<u8>,
    },
    Recovering,
    Recovered,
    Burned,
}

#[derive(Serialize)]
struct PublicError {
    code: &'static str,
    message: &'static str,
}

enum WebFailure {
    Protocol(ProtocolError),
    Public {
        code: &'static str,
        message: &'static str,
    },
}

struct RecoveryState {
    epoch: u64,
    proof_sent: bool,
    peer_proof_verified: bool,
    local_contribution: Option<Zeroizing<[u8; 32]>>,
}

impl WebFailure {
    const fn state(code: &'static str, message: &'static str) -> Self {
        Self::Public { code, message }
    }

    fn into_js(self) -> JsValue {
        let public = match self {
            Self::Protocol(error) => protocol_public_error(error),
            Self::Public { code, message } => PublicError { code, message },
        };
        serde_wasm_bindgen::to_value(&public)
            .unwrap_or_else(|_| JsValue::from_str("internal error"))
    }
}

impl From<ProtocolError> for WebFailure {
    fn from(error: ProtocolError) -> Self {
        Self::Protocol(error)
    }
}

/// A narrow WebAssembly owner for one BlindWire Protocol 2.1 session.
#[wasm_bindgen]
pub struct WebSession {
    role: Role,
    room: [u8; 32],
    _token: Option<Zeroizing<Vec<u8>>>,
    noise: NoiseSession,
    relay_confirmed: bool,
    local_contribution: Option<Zeroizing<[u8; 32]>>,
    continuity: Option<ContinuitySecret>,
    local_verified: bool,
    peer_verified: bool,
    pending: HashMap<MessageId, Zeroizing<Vec<u8>>>,
    deduplicator: MessageDeduplicator,
    received_ids: VecDeque<MessageId>,
    epoch: u64,
    recovery: Option<RecoveryState>,
    terminated: bool,
}

#[wasm_bindgen]
impl WebSession {
    /// Construct a role-bound session from canonical binary room and token data.
    #[wasm_bindgen(constructor)]
    pub fn new(role: u8, room: &[u8], token: Option<Vec<u8>>) -> Result<WebSession, JsValue> {
        Self::new_inner(role, room, token).map_err(WebFailure::into_js)
    }

    /// Start the Noise XX handshake. Only the initiator may call this method.
    pub fn start_handshake(&mut self) -> Result<JsValue, JsValue> {
        let result = (|| {
            self.ensure_live()?;
            if self.role != Role::Initiator || self.noise.is_handshake_complete() {
                return Err(WebFailure::state("WRONG_STATE", "operation not allowed"));
            }
            let payload = self.noise.write_handshake()?;
            Ok(CallResult::events(vec![PublicEvent::Outbound {
                frame: Frame::handshake(payload)?.to_wire(),
            }]))
        })();
        result_to_js(result)
    }

    /// Accept one complete length-prefixed peer frame.
    pub fn receive_frame(&mut self, wire: &[u8]) -> Result<JsValue, JsValue> {
        if let Err(error) = self.ensure_live() {
            return Err(error.into_js());
        }
        match self.receive_frame_inner(wire) {
            Ok(result) => serialize_result(&result),
            Err(error) => {
                self.terminate_local();
                Err(error.into_js())
            }
        }
    }

    /// Record the relay's two-sided HANDSHAKE_CONFIRMED transition.
    pub fn relay_handshake_confirmed(&mut self) -> Result<JsValue, JsValue> {
        let result = (|| {
            self.ensure_live()?;
            if !self.noise.is_handshake_complete()
                || self.relay_confirmed
                || self.local_contribution.is_some()
            {
                return Err(WebFailure::state("WRONG_STATE", "operation not allowed"));
            }
            let contribution = random_array::<32>()?;
            let frame =
                self.encrypt_envelope(&ApplicationEnvelope::RecoveryContribution(contribution))?;
            self.local_contribution = Some(Zeroizing::new(contribution));
            self.relay_confirmed = true;
            Ok(CallResult::events(vec![PublicEvent::Outbound { frame }]))
        })();
        result_to_js(result)
    }

    /// Confirm that the local user accepted the displayed SAS.
    pub fn confirm_user_verified(&mut self) -> Result<JsValue, JsValue> {
        let result = (|| {
            self.ensure_live()?;
            if self.continuity.is_none() {
                return Err(WebFailure::state(
                    "VERIFICATION_NOT_READY",
                    "verification not ready",
                ));
            }
            if self.local_verified {
                return Ok(CallResult::events(Vec::new()));
            }
            let frame = self.encrypt_envelope(&ApplicationEnvelope::UserVerified)?;
            self.local_verified = true;
            Ok(CallResult::events(vec![PublicEvent::Outbound { frame }]))
        })();
        result_to_js(result)
    }

    /// Encrypt a text message after both users have confirmed the SAS.
    pub fn send_text(&mut self, text: &str) -> Result<JsValue, JsValue> {
        let result = (|| {
            self.ensure_live()?;
            self.require_two_sided_verification()?;
            let id = MessageId::generate()?;
            let encoded = ApplicationEnvelope::Text {
                id,
                body: text.to_owned(),
            }
            .encode()?;
            let ciphertext = self.noise.encrypt(&encoded)?;
            let frame = Frame::data(ciphertext)?.to_wire();
            self.pending.insert(id, encoded);
            Ok(CallResult {
                events: vec![PublicEvent::Outbound { frame }],
                message_id: Some(id.as_bytes().to_vec()),
            })
        })();
        result_to_js(result)
    }

    /// Encrypt a room-burn control and irreversibly terminate local state.
    /// Begin an authenticated recovery epoch over a fresh Noise XX session.
    /// Consume this session into a worker-only snapshot plaintext.
    ///
    /// The dedicated worker must encrypt the returned bytes with its
    /// non-exportable Web Crypto key before persistence.
    pub fn recovery_snapshot_for_worker_storage(
        mut self,
        expires_at_ms: u64,
    ) -> Result<Vec<u8>, JsValue> {
        let result = self.encode_worker_snapshot(expires_at_ms);
        self.terminate_local();
        result.map_err(WebFailure::into_js)
    }

    /// Restore a worker-decrypted snapshot into recovery-only state.
    pub fn restore_worker_snapshot(snapshot: &[u8], now_ms: u64) -> Result<WebSession, JsValue> {
        Self::decode_worker_snapshot(snapshot, now_ms).map_err(WebFailure::into_js)
    }

    pub fn begin_recovery(&mut self, epoch: u64) -> Result<JsValue, JsValue> {
        let result = (|| {
            self.ensure_live()?;
            if self.continuity.is_none()
                || self.recovery.is_some()
                || epoch != self.epoch.saturating_add(1)
            {
                return Err(WebFailure::state(
                    "RECOVERY_UNAVAILABLE",
                    "recovery unavailable",
                ));
            }
            self.noise.terminate();
            self.noise = match self.role {
                Role::Initiator => NoiseSession::new_initiator()?,
                Role::Responder => NoiseSession::new_responder()?,
            };
            self.recovery = Some(RecoveryState {
                epoch,
                proof_sent: false,
                peer_proof_verified: false,
                local_contribution: None,
            });
            let mut events = vec![PublicEvent::Recovering];
            if self.role == Role::Initiator {
                let first = self.noise.write_handshake()?;
                events.push(PublicEvent::Outbound {
                    frame: Frame::handshake(first)?.to_wire(),
                });
            }
            Ok(CallResult::events(events))
        })();
        result_to_js(result)
    }

    /// Accept an encrypted peer resume proof frame during recovery.
    pub fn accept_resume_proof(&mut self, wire: &[u8]) -> Result<JsValue, JsValue> {
        if self.recovery.is_none() {
            return Err(
                WebFailure::state("RECOVERY_UNAVAILABLE", "recovery unavailable").into_js(),
            );
        }
        self.receive_frame(wire)
    }

    pub fn burn(&mut self) -> Result<JsValue, JsValue> {
        let result = (|| {
            self.ensure_live()?;
            if !self.noise.is_handshake_complete() {
                return Err(WebFailure::state("WRONG_STATE", "operation not allowed"));
            }
            let frame = self.encrypt_envelope(&ApplicationEnvelope::BurnRoom)?;
            self.terminate_local();
            Ok(CallResult::events(vec![
                PublicEvent::Outbound { frame },
                PublicEvent::Burned,
            ]))
        })();
        result_to_js(result)
    }
}

impl WebSession {
    fn new_inner(role_byte: u8, room: &[u8], token: Option<Vec<u8>>) -> Result<Self, WebFailure> {
        let room = room
            .try_into()
            .map_err(|_| WebFailure::state("INVALID_ARGUMENT", "invalid room identifier"))?;
        let (role, noise, token) = match (role_byte, token) {
            (ROLE_INITIATOR, None) => (Role::Initiator, NoiseSession::new_initiator()?, None),
            (ROLE_RESPONDER, Some(token)) if token.len() == 32 => (
                Role::Responder,
                NoiseSession::new_responder()?,
                Some(Zeroizing::new(token)),
            ),
            (ROLE_INITIATOR | ROLE_RESPONDER, _) => {
                return Err(WebFailure::state(
                    "INVALID_ARGUMENT",
                    "invalid role capability",
                ));
            }
            _ => return Err(WebFailure::state("INVALID_ARGUMENT", "invalid role")),
        };
        Ok(Self {
            role,
            room,
            _token: token,
            noise,
            relay_confirmed: false,
            local_contribution: None,
            continuity: None,
            local_verified: false,
            peer_verified: false,
            pending: HashMap::new(),
            deduplicator: MessageDeduplicator::new(),
            received_ids: VecDeque::with_capacity(DEDUPLICATION_CAPACITY),
            epoch: 0,
            recovery: None,
            terminated: false,
        })
    }

    fn receive_frame_inner(&mut self, wire: &[u8]) -> Result<CallResult, WebFailure> {
        let frame = parse_wire(wire)?;
        if !self.noise.is_handshake_complete() {
            if frame.msg_type() != MessageType::Handshake {
                return Err(ProtocolError::UnexpectedMessageType.into());
            }
            self.noise.read_handshake(frame.payload())?;
            let mut events = Vec::new();
            if !self.noise.is_handshake_complete() && self.noise.is_my_turn()? {
                let response = self.noise.write_handshake()?;
                events.push(PublicEvent::Outbound {
                    frame: Frame::handshake(response)?.to_wire(),
                });
            }
            if self.noise.is_handshake_complete() && self.recovery.is_some() {
                self.append_local_resume_proof(&mut events)?;
            }
            return Ok(CallResult::events(events));
        }

        if frame.msg_type() != MessageType::Data {
            return Err(ProtocolError::UnexpectedMessageType.into());
        }
        let plaintext = Zeroizing::new(self.noise.decrypt(frame.payload())?);
        self.receive_envelope(ApplicationEnvelope::decode(&plaintext)?)
    }

    fn receive_envelope(
        &mut self,
        envelope: ApplicationEnvelope,
    ) -> Result<CallResult, WebFailure> {
        let mut events = Vec::new();
        match envelope {
            ApplicationEnvelope::RecoveryContribution(peer) => {
                if self.recovery.is_some() {
                    self.finish_recovery(peer, &mut events)?;
                    return Ok(CallResult::events(events));
                }
                if !self.relay_confirmed || self.continuity.is_some() {
                    return Err(ProtocolError::UnexpectedMessageType.into());
                }
                let local = self
                    .local_contribution
                    .take()
                    .ok_or(ProtocolError::UnexpectedMessageType)?;
                let (initiator, responder) = match self.role {
                    Role::Initiator => (&*local, &peer),
                    Role::Responder => (&peer, &*local),
                };
                self.continuity = Some(derive_continuity_secret(&self.room, initiator, responder)?);
                let fingerprint = self
                    .noise
                    .fingerprint_bytes()
                    .ok_or(ProtocolError::HandshakeFailed)?;
                events.push(PublicEvent::Verification {
                    emojis: sas::generate(&fingerprint, &self.room),
                    numeric: sas::generate_numeric(&fingerprint, &self.room),
                });
            }
            ApplicationEnvelope::UserVerified => {
                if self.continuity.is_none() {
                    return Err(ProtocolError::UnexpectedMessageType.into());
                }
                if !self.peer_verified {
                    self.peer_verified = true;
                    events.push(PublicEvent::PeerVerified);
                }
            }
            ApplicationEnvelope::Text { id, body } => {
                self.require_two_sided_verification()?;
                let first = self.deduplicator.observe(id);
                events.push(PublicEvent::Outbound {
                    frame: self.encrypt_envelope(&ApplicationEnvelope::Ack { id })?,
                });
                if first {
                    self.received_ids.push_back(id);
                    if self.received_ids.len() > DEDUPLICATION_CAPACITY {
                        self.received_ids.pop_front();
                    }
                    events.push(PublicEvent::Text {
                        id: id.as_bytes().to_vec(),
                        text: body,
                    });
                }
            }
            ApplicationEnvelope::Ack { id } => {
                self.require_two_sided_verification()?;
                if self.pending.remove(&id).is_some() {
                    events.push(PublicEvent::Acknowledgement {
                        id: id.as_bytes().to_vec(),
                    });
                }
            }
            ApplicationEnvelope::BurnRoom => {
                self.terminate_local();
                events.push(PublicEvent::Burned);
            }
            ApplicationEnvelope::ResumeProof { epoch, mac } => {
                self.accept_resume_proof_envelope(epoch, &mac, &mut events)?;
            }
        }
        Ok(CallResult::events(events))
    }

    fn encode_worker_snapshot(&mut self, expires_at_ms: u64) -> Result<Vec<u8>, WebFailure> {
        self.ensure_live()?;
        if self.recovery.is_some()
            || !self.local_verified
            || !self.peer_verified
            || expires_at_ms == 0
        {
            return Err(WebFailure::state(
                "RECOVERY_UNAVAILABLE",
                "recovery unavailable",
            ));
        }
        let continuity = self
            .continuity
            .take()
            .ok_or_else(|| WebFailure::state("RECOVERY_UNAVAILABLE", "recovery unavailable"))?;
        let secret = continuity.into_worker_snapshot_secret();
        let pending_count = u16::try_from(self.pending.len())
            .map_err(|_| WebFailure::state("SNAPSHOT_TOO_LARGE", "snapshot too large"))?;
        let received_count = u16::try_from(self.received_ids.len())
            .map_err(|_| WebFailure::state("SNAPSHOT_TOO_LARGE", "snapshot too large"))?;

        let mut encoded = Zeroizing::new(Vec::new());
        encoded.extend_from_slice(SNAPSHOT_MAGIC);
        encoded.push(SNAPSHOT_VERSION);
        encoded.push(match self.role {
            Role::Initiator => ROLE_INITIATOR,
            Role::Responder => ROLE_RESPONDER,
        });
        encoded.extend_from_slice(&self.room);
        encoded.extend_from_slice(&self.epoch.to_be_bytes());
        encoded.extend_from_slice(&expires_at_ms.to_be_bytes());
        encoded.push(0b0000_0111);
        encoded.extend_from_slice(&secret[..]);
        encoded.extend_from_slice(&pending_count.to_be_bytes());
        for plaintext in self.pending.values() {
            let length = u16::try_from(plaintext.len())
                .map_err(|_| WebFailure::state("SNAPSHOT_TOO_LARGE", "snapshot too large"))?;
            encoded.extend_from_slice(&length.to_be_bytes());
            encoded.extend_from_slice(plaintext);
        }
        encoded.extend_from_slice(&received_count.to_be_bytes());
        for id in &self.received_ids {
            encoded.extend_from_slice(id.as_bytes());
        }
        if encoded.len() + SNAPSHOT_DIGEST_LENGTH > MAX_SNAPSHOT_LENGTH {
            return Err(WebFailure::state(
                "SNAPSHOT_TOO_LARGE",
                "snapshot too large",
            ));
        }
        let digest = Sha256::digest(&encoded[..]);
        encoded.extend_from_slice(&digest);
        Ok(encoded.to_vec())
    }

    fn decode_worker_snapshot(snapshot: &[u8], now_ms: u64) -> Result<Self, WebFailure> {
        if snapshot.len() < 4 + 1 + 1 + 32 + 8 + 8 + 1 + 32 + 2 + 2 + 32
            || snapshot.len() > MAX_SNAPSHOT_LENGTH
        {
            return Err(invalid_snapshot());
        }
        let snapshot = Zeroizing::new(snapshot.to_vec());
        let content_length = snapshot.len() - SNAPSHOT_DIGEST_LENGTH;
        let expected = Sha256::digest(&snapshot[..content_length]);
        if expected.as_slice() != &snapshot[content_length..] {
            return Err(invalid_snapshot());
        }
        let mut cursor = SnapshotCursor::new(&snapshot[..content_length]);
        if cursor.array::<4>()? != *SNAPSHOT_MAGIC || cursor.byte()? != SNAPSHOT_VERSION {
            return Err(invalid_snapshot());
        }
        let role = match cursor.byte()? {
            ROLE_INITIATOR => Role::Initiator,
            ROLE_RESPONDER => Role::Responder,
            _ => return Err(invalid_snapshot()),
        };
        let room = cursor.array::<32>()?;
        let epoch = u64::from_be_bytes(cursor.array::<8>()?);
        let expires_at_ms = u64::from_be_bytes(cursor.array::<8>()?);
        if now_ms > expires_at_ms {
            return Err(WebFailure::state("SNAPSHOT_EXPIRED", "snapshot expired"));
        }
        let flags = cursor.byte()?;
        if flags != 0b0000_0111 {
            return Err(invalid_snapshot());
        }
        let secret = Zeroizing::new(cursor.array::<32>()?);
        let continuity = ContinuitySecret::from_worker_snapshot_secret(secret);
        let pending_count = usize::from(u16::from_be_bytes(cursor.array::<2>()?));
        let mut pending = HashMap::with_capacity(pending_count);
        for _ in 0..pending_count {
            let length = usize::from(u16::from_be_bytes(cursor.array::<2>()?));
            let plaintext = Zeroizing::new(cursor.bytes(length)?.to_vec());
            let id = match ApplicationEnvelope::decode(&plaintext)? {
                ApplicationEnvelope::Text { id, .. } => id,
                _ => return Err(invalid_snapshot()),
            };
            if pending.insert(id, plaintext).is_some() {
                return Err(invalid_snapshot());
            }
        }
        let received_count = usize::from(u16::from_be_bytes(cursor.array::<2>()?));
        if received_count > DEDUPLICATION_CAPACITY {
            return Err(invalid_snapshot());
        }
        let mut deduplicator = MessageDeduplicator::new();
        let mut received_ids = VecDeque::with_capacity(DEDUPLICATION_CAPACITY);
        for _ in 0..received_count {
            let id = MessageId::from_bytes(cursor.array::<16>()?);
            if !deduplicator.observe(id) {
                return Err(invalid_snapshot());
            }
            received_ids.push_back(id);
        }
        if !cursor.is_finished() {
            return Err(invalid_snapshot());
        }
        let noise = match role {
            Role::Initiator => NoiseSession::new_initiator()?,
            Role::Responder => NoiseSession::new_responder()?,
        };
        Ok(Self {
            role,
            room,
            _token: None,
            noise,
            relay_confirmed: true,
            local_contribution: None,
            continuity: Some(continuity),
            local_verified: true,
            peer_verified: true,
            pending,
            deduplicator,
            received_ids,
            epoch,
            recovery: None,
            terminated: false,
        })
    }

    fn append_local_resume_proof(
        &mut self,
        events: &mut Vec<PublicEvent>,
    ) -> Result<(), WebFailure> {
        let recovery = self
            .recovery
            .as_ref()
            .ok_or(ProtocolError::UnexpectedMessageType)?;
        if recovery.proof_sent {
            return Err(ProtocolError::UnexpectedMessageType.into());
        }
        let epoch = recovery.epoch;
        let fingerprint = self
            .noise
            .fingerprint_bytes()
            .ok_or(ProtocolError::HandshakeFailed)?;
        let continuity = self
            .continuity
            .as_ref()
            .ok_or(ProtocolError::InvalidResumeProof)?;
        let mac = compute_resume_proof(continuity, &self.room, self.role, epoch, &fingerprint);
        let frame = self.encrypt_envelope(&ApplicationEnvelope::ResumeProof { epoch, mac })?;
        self.recovery
            .as_mut()
            .ok_or(ProtocolError::UnexpectedMessageType)?
            .proof_sent = true;
        events.push(PublicEvent::Outbound { frame });
        Ok(())
    }

    fn accept_resume_proof_envelope(
        &mut self,
        epoch: u64,
        mac: &[u8; 32],
        events: &mut Vec<PublicEvent>,
    ) -> Result<(), WebFailure> {
        let recovery = self
            .recovery
            .as_ref()
            .ok_or(ProtocolError::UnexpectedMessageType)?;
        if !recovery.proof_sent || recovery.peer_proof_verified || recovery.epoch != epoch {
            return Err(ProtocolError::InvalidResumeProof.into());
        }
        let fingerprint = self
            .noise
            .fingerprint_bytes()
            .ok_or(ProtocolError::HandshakeFailed)?;
        let continuity = self
            .continuity
            .as_ref()
            .ok_or(ProtocolError::InvalidResumeProof)?;
        let peer_role = match self.role {
            Role::Initiator => Role::Responder,
            Role::Responder => Role::Initiator,
        };
        verify_resume_proof(continuity, &self.room, peer_role, epoch, &fingerprint, mac)?;

        let contribution = random_array::<32>()?;
        let frame =
            self.encrypt_envelope(&ApplicationEnvelope::RecoveryContribution(contribution))?;
        let recovery = self
            .recovery
            .as_mut()
            .ok_or(ProtocolError::UnexpectedMessageType)?;
        recovery.peer_proof_verified = true;
        recovery.local_contribution = Some(Zeroizing::new(contribution));
        events.push(PublicEvent::Outbound { frame });
        Ok(())
    }

    fn finish_recovery(
        &mut self,
        peer_contribution: [u8; 32],
        events: &mut Vec<PublicEvent>,
    ) -> Result<(), WebFailure> {
        let mut recovery = self
            .recovery
            .take()
            .ok_or(ProtocolError::UnexpectedMessageType)?;
        if !recovery.peer_proof_verified {
            return Err(ProtocolError::InvalidResumeProof.into());
        }
        let local = recovery
            .local_contribution
            .take()
            .ok_or(ProtocolError::UnexpectedMessageType)?;
        let previous = self
            .continuity
            .take()
            .ok_or(ProtocolError::InvalidResumeProof)?;
        let (initiator, responder) = match self.role {
            Role::Initiator => (&*local, &peer_contribution),
            Role::Responder => (&peer_contribution, &*local),
        };
        self.continuity = Some(ratchet_continuity_secret(
            previous,
            &self.room,
            recovery.epoch,
            initiator,
            responder,
        )?);
        self.epoch = recovery.epoch;
        events.push(PublicEvent::Recovered);

        let pending = std::mem::take(&mut self.pending);
        for plaintext in pending.values() {
            let ciphertext = self.noise.encrypt(plaintext)?;
            events.push(PublicEvent::Outbound {
                frame: Frame::data(ciphertext)?.to_wire(),
            });
        }
        self.pending = pending;
        Ok(())
    }

    fn encrypt_envelope(&mut self, envelope: &ApplicationEnvelope) -> Result<Vec<u8>, WebFailure> {
        let plaintext = envelope.encode()?;
        let ciphertext = self.noise.encrypt(&plaintext)?;
        Ok(Frame::data(ciphertext)?.to_wire())
    }

    fn require_two_sided_verification(&self) -> Result<(), WebFailure> {
        if self.local_verified && self.peer_verified {
            Ok(())
        } else {
            Err(WebFailure::state(
                "VERIFICATION_REQUIRED",
                "verification required",
            ))
        }
    }

    fn ensure_live(&self) -> Result<(), WebFailure> {
        if self.terminated || self.noise.is_terminated() {
            Err(WebFailure::state(
                "SESSION_TERMINATED",
                "session terminated",
            ))
        } else {
            Ok(())
        }
    }

    fn terminate_local(&mut self) {
        if !self.terminated {
            self.noise.terminate();
            self.local_contribution = None;
            self.continuity = None;
            self.pending.clear();
            self.terminated = true;
        }
    }
}

impl CallResult {
    fn events(events: Vec<PublicEvent>) -> Self {
        Self {
            events,
            message_id: None,
        }
    }
}

impl Drop for WebSession {
    fn drop(&mut self) {
        self.terminate_local();
    }
}

struct SnapshotCursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> SnapshotCursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn byte(&mut self) -> Result<u8, WebFailure> {
        Ok(self.array::<1>()?[0])
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], WebFailure> {
        self.bytes(N)?.try_into().map_err(|_| invalid_snapshot())
    }

    fn bytes(&mut self, length: usize) -> Result<&'a [u8], WebFailure> {
        let end = self
            .position
            .checked_add(length)
            .ok_or_else(invalid_snapshot)?;
        let bytes = self
            .bytes
            .get(self.position..end)
            .ok_or_else(invalid_snapshot)?;
        self.position = end;
        Ok(bytes)
    }

    fn is_finished(&self) -> bool {
        self.position == self.bytes.len()
    }
}

fn invalid_snapshot() -> WebFailure {
    WebFailure::state("INVALID_SNAPSHOT", "invalid recovery snapshot")
}

fn parse_wire(wire: &[u8]) -> Result<Frame, WebFailure> {
    let wire = Zeroizing::new(wire.to_vec());
    if wire.len() < LENGTH_PREFIX_SIZE {
        return Err(ProtocolError::MessageEmpty.into());
    }
    let prefix = [wire[0], wire[1]];
    let body_length = Frame::read_length(&prefix)?;
    if wire.len() != LENGTH_PREFIX_SIZE + body_length {
        return Err(ProtocolError::InvalidApplicationEnvelope.into());
    }
    Frame::parse(&wire[LENGTH_PREFIX_SIZE..]).map_err(Into::into)
}

fn result_to_js(result: Result<CallResult, WebFailure>) -> Result<JsValue, JsValue> {
    match result {
        Ok(result) => serialize_result(&result),
        Err(error) => Err(error.into_js()),
    }
}

fn serialize_result(result: &CallResult) -> Result<JsValue, JsValue> {
    serde_wasm_bindgen::to_value(result)
        .map_err(|_| WebFailure::state("INTERNAL_ERROR", "internal error").into_js())
}

const fn protocol_public_error(error: ProtocolError) -> PublicError {
    match error {
        ProtocolError::SessionTerminated => PublicError {
            code: "SESSION_TERMINATED",
            message: "session terminated",
        },
        ProtocolError::MessageTooLarge | ProtocolError::PlaintextTooLarge => PublicError {
            code: "MESSAGE_TOO_LARGE",
            message: "message too large",
        },
        ProtocolError::EmptyPlaintext
        | ProtocolError::InvalidUtf8
        | ProtocolError::NulByteInPlaintext => PublicError {
            code: "INVALID_TEXT",
            message: "invalid text",
        },
        ProtocolError::EntropyUnavailable => PublicError {
            code: "ENTROPY_UNAVAILABLE",
            message: "secure randomness unavailable",
        },
        ProtocolError::HandshakeFailed
        | ProtocolError::DecryptionFailed
        | ProtocolError::InvalidResumeProof => PublicError {
            code: "CRYPTOGRAPHIC_FAILURE",
            message: "secure session failed",
        },
        _ => PublicError {
            code: "PROTOCOL_ERROR",
            message: "invalid secure-session input",
        },
    }
}
