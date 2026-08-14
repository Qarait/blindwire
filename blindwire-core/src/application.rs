//! Protocol 2.1 application envelopes.

use std::collections::{HashSet, VecDeque};

use zeroize::Zeroizing;

use crate::{entropy::random_array, frame::validate_plaintext, ProtocolError};

const MESSAGE_ID_LENGTH: usize = 16;
const TEXT_HEADER_LENGTH: usize = 1 + MESSAGE_ID_LENGTH + 2;
const DEDUPLICATION_CAPACITY: usize = 256;

const TEXT_TYPE: u8 = 0x01;
const ACK_TYPE: u8 = 0x02;
const USER_VERIFIED_TYPE: u8 = 0x03;
const RECOVERY_CONTRIBUTION_TYPE: u8 = 0x04;
const RESUME_PROOF_TYPE: u8 = 0x05;
const BURN_ROOM_TYPE: u8 = 0x06;

/// A fixed-width identifier for an application message.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct MessageId([u8; MESSAGE_ID_LENGTH]);

impl MessageId {
    /// Generate an identifier from the platform cryptographic entropy source.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::EntropyUnavailable`] when secure randomness is
    /// unavailable.
    pub fn generate() -> Result<Self, ProtocolError> {
        random_array().map(Self)
    }

    /// Construct an identifier from its canonical bytes.
    pub const fn from_bytes(bytes: [u8; MESSAGE_ID_LENGTH]) -> Self {
        Self(bytes)
    }

    /// Borrow the canonical bytes of this identifier.
    pub const fn as_bytes(&self) -> &[u8; MESSAGE_ID_LENGTH] {
        &self.0
    }
}

/// A canonical Protocol 2.1 application message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ApplicationEnvelope {
    /// A user-authored UTF-8 text message.
    Text {
        /// The message identifier used for acknowledgement and deduplication.
        id: MessageId,
        /// The validated plaintext body.
        body: String,
    },
    /// An acknowledgement for a text message.
    Ack {
        /// The acknowledged message identifier.
        id: MessageId,
    },
    /// Confirmation that the local user verified the peer's SAS.
    UserVerified,
    /// A 32-byte recovery contribution.
    RecoveryContribution([u8; 32]),
    /// A proof authorizing session resumption for an epoch.
    ResumeProof {
        /// The monotonically increasing recovery epoch.
        epoch: u64,
        /// The 32-byte message authentication code.
        mac: [u8; 32],
    },
    /// An instruction to irreversibly burn the room.
    BurnRoom,
}

impl ApplicationEnvelope {
    /// Encode the envelope using the canonical Protocol 2.1 binary format.
    ///
    /// # Errors
    ///
    /// Returns a plaintext validation error when a text body is empty, too
    /// large, or contains a NUL byte.
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>, ProtocolError> {
        let mut encoded = match self {
            Self::Text { id, body } => {
                validate_plaintext(body.as_bytes())?;
                let body_length =
                    u16::try_from(body.len()).map_err(|_| ProtocolError::PlaintextTooLarge)?;
                let mut bytes = Vec::with_capacity(TEXT_HEADER_LENGTH + body.len());
                bytes.push(TEXT_TYPE);
                bytes.extend_from_slice(id.as_bytes());
                bytes.extend_from_slice(&body_length.to_be_bytes());
                bytes.extend_from_slice(body.as_bytes());
                bytes
            }
            Self::Ack { id } => {
                let mut bytes = Vec::with_capacity(1 + MESSAGE_ID_LENGTH);
                bytes.push(ACK_TYPE);
                bytes.extend_from_slice(id.as_bytes());
                bytes
            }
            Self::UserVerified => vec![USER_VERIFIED_TYPE],
            Self::RecoveryContribution(contribution) => {
                let mut bytes = Vec::with_capacity(1 + contribution.len());
                bytes.push(RECOVERY_CONTRIBUTION_TYPE);
                bytes.extend_from_slice(contribution);
                bytes
            }
            Self::ResumeProof { epoch, mac } => {
                let mut bytes = Vec::with_capacity(1 + size_of::<u64>() + mac.len());
                bytes.push(RESUME_PROOF_TYPE);
                bytes.extend_from_slice(&epoch.to_be_bytes());
                bytes.extend_from_slice(mac);
                bytes
            }
            Self::BurnRoom => vec![BURN_ROOM_TYPE],
        };

        Ok(Zeroizing::new(std::mem::take(&mut encoded)))
    }

    /// Decode one canonical Protocol 2.1 application envelope.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::UnknownApplicationType`] for an unknown
    /// discriminator, [`ProtocolError::InvalidApplicationEnvelope`] for any
    /// truncated or trailing data, or a plaintext validation error for an
    /// invalid text body.
    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        let discriminator = bytes
            .first()
            .copied()
            .ok_or(ProtocolError::InvalidApplicationEnvelope)?;

        match discriminator {
            TEXT_TYPE => Self::decode_text(bytes),
            ACK_TYPE => {
                require_exact_length(bytes, 1 + MESSAGE_ID_LENGTH)?;
                Ok(Self::Ack {
                    id: MessageId::from_bytes(read_array(&bytes[1..])?),
                })
            }
            USER_VERIFIED_TYPE => {
                require_exact_length(bytes, 1)?;
                Ok(Self::UserVerified)
            }
            RECOVERY_CONTRIBUTION_TYPE => {
                require_exact_length(bytes, 1 + 32)?;
                Ok(Self::RecoveryContribution(read_array(&bytes[1..])?))
            }
            RESUME_PROOF_TYPE => {
                require_exact_length(bytes, 1 + size_of::<u64>() + 32)?;
                Ok(Self::ResumeProof {
                    epoch: u64::from_be_bytes(read_array(&bytes[1..9])?),
                    mac: read_array(&bytes[9..])?,
                })
            }
            BURN_ROOM_TYPE => {
                require_exact_length(bytes, 1)?;
                Ok(Self::BurnRoom)
            }
            _ => Err(ProtocolError::UnknownApplicationType),
        }
    }

    fn decode_text(bytes: &[u8]) -> Result<Self, ProtocolError> {
        if bytes.len() < TEXT_HEADER_LENGTH {
            return Err(ProtocolError::InvalidApplicationEnvelope);
        }

        let body_length = usize::from(u16::from_be_bytes(read_array(&bytes[17..19])?));
        let encoded_length = TEXT_HEADER_LENGTH
            .checked_add(body_length)
            .ok_or(ProtocolError::InvalidApplicationEnvelope)?;
        require_exact_length(bytes, encoded_length)?;

        let body = validate_plaintext(&bytes[TEXT_HEADER_LENGTH..])?.to_owned();
        Ok(Self::Text {
            id: MessageId::from_bytes(read_array(&bytes[1..17])?),
            body,
        })
    }
}

fn require_exact_length(bytes: &[u8], expected: usize) -> Result<(), ProtocolError> {
    if bytes.len() != expected {
        return Err(ProtocolError::InvalidApplicationEnvelope);
    }
    Ok(())
}

fn read_array<const N: usize>(bytes: &[u8]) -> Result<[u8; N], ProtocolError> {
    bytes
        .try_into()
        .map_err(|_| ProtocolError::InvalidApplicationEnvelope)
}

/// A bounded record of recently observed message identifiers.
pub struct MessageDeduplicator {
    order: VecDeque<MessageId>,
    seen: HashSet<MessageId>,
}

impl MessageDeduplicator {
    /// Create an empty deduplicator with capacity for 256 identifiers.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record an identifier, returning `true` only when it was not present.
    ///
    /// Once 256 identifiers are retained, observing a new identifier evicts
    /// the oldest retained identifier.
    pub fn observe(&mut self, id: MessageId) -> bool {
        if !self.seen.insert(id) {
            return false;
        }

        self.order.push_back(id);
        if self.order.len() > DEDUPLICATION_CAPACITY {
            if let Some(oldest) = self.order.pop_front() {
                self.seen.remove(&oldest);
            }
        }
        true
    }
}

impl Default for MessageDeduplicator {
    fn default() -> Self {
        Self {
            order: VecDeque::with_capacity(DEDUPLICATION_CAPACITY),
            seen: HashSet::with_capacity(DEDUPLICATION_CAPACITY),
        }
    }
}
