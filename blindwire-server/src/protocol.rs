#![forbid(unsafe_code)]

pub const MAX_RELAY_FRAME: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignalingVersion {
    V3,
    V4,
}

impl SignalingVersion {
    pub const fn as_byte(self) -> u8 {
        match self {
            Self::V3 => 0x03,
            Self::V4 => 0x04,
        }
    }

    fn parse(byte: u8) -> Result<Self, ParseError> {
        match byte {
            0x03 => Ok(Self::V3),
            0x04 => Ok(Self::V4),
            _ => Err(ParseError::Version),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Initiator,
    Responder,
}

impl Role {
    pub const fn as_byte(self) -> u8 {
        match self {
            Self::Initiator => b'i',
            Self::Responder => b'r',
        }
    }

    pub const fn other(self) -> Self {
        match self {
            Self::Initiator => Self::Responder,
            Self::Responder => Self::Initiator,
        }
    }

    fn parse(byte: u8) -> Result<Self, ParseError> {
        match byte {
            b'i' => Ok(Self::Initiator),
            b'r' => Ok(Self::Responder),
            _ => Err(ParseError::Format),
        }
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    RoleTaken = 0x01,
    InvalidFormat = 0x02,
    UnknownOpcode = 0x03,
    Unauthorized = 0x04,
    QueueFull = 0x05,
    VersionMismatch = 0x06,
    RateLimitExceeded = 0x07,
    PinRequired = 0x08,
    Expired = 0x09,
}

impl ErrorCode {
    fn parse(byte: u8) -> Result<Self, ParseError> {
        match byte {
            0x01 => Ok(Self::RoleTaken),
            0x02 => Ok(Self::InvalidFormat),
            0x03 => Ok(Self::UnknownOpcode),
            0x04 => Ok(Self::Unauthorized),
            0x05 => Ok(Self::QueueFull),
            0x06 => Ok(Self::VersionMismatch),
            0x07 => Ok(Self::RateLimitExceeded),
            0x08 => Ok(Self::PinRequired),
            0x09 => Ok(Self::Expired),
            _ => Err(ParseError::Format),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    Format,
    Version,
    Opcode,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientPacket {
    Join {
        role: Role,
        room: [u8; 32],
        token: Option<[u8; 32]>,
    },
    Relay(Vec<u8>),
    Quit,
    HandshakeComplete,
    RegisterRecovery([u8; 32]),
    Resume {
        role: Role,
        room: [u8; 32],
        capability: [u8; 32],
        epoch: u64,
    },
    Burn,
}

impl ClientPacket {
    pub fn parse_v4(data: &[u8]) -> Result<Self, ParseError> {
        let Some(&opcode) = data.first() else {
            return Err(ParseError::Format);
        };

        match opcode {
            0x00 => {
                if data.len() != 35 && data.len() != 67 {
                    return Err(ParseError::Format);
                }
                let role = Role::parse(data[1])?;
                if SignalingVersion::parse(data[2])? != SignalingVersion::V4 {
                    return Err(ParseError::Version);
                }
                if (role == Role::Initiator && data.len() != 35)
                    || (role == Role::Responder && data.len() != 67)
                {
                    return Err(ParseError::Format);
                }
                let room = read_array::<32>(&data[3..35])?;
                let token = if role == Role::Responder {
                    Some(read_array::<32>(&data[35..67])?)
                } else {
                    None
                };
                Ok(Self::Join { role, room, token })
            }
            0x01 => {
                validate_relay(data)?;
                Ok(Self::Relay(data.to_vec()))
            }
            0x02 if data.len() == 1 => Ok(Self::Quit),
            0x03 if data.len() == 1 => Ok(Self::HandshakeComplete),
            0x04 if data.len() == 33 => Ok(Self::RegisterRecovery(read_array(&data[1..])?)),
            0x05 => {
                if data.len() != 75 {
                    return Err(ParseError::Format);
                }
                let role = Role::parse(data[1])?;
                if SignalingVersion::parse(data[2])? != SignalingVersion::V4 {
                    return Err(ParseError::Version);
                }
                Ok(Self::Resume {
                    role,
                    room: read_array(&data[3..35])?,
                    capability: read_array(&data[35..67])?,
                    epoch: u64::from_be_bytes(read_array(&data[67..75])?),
                })
            }
            0x06 if data.len() == 1 => Ok(Self::Burn),
            0x02..=0x06 => Err(ParseError::Format),
            _ => Err(ParseError::Opcode),
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::Join { role, room, token } => {
                let mut encoded = Vec::with_capacity(if token.is_some() { 67 } else { 35 });
                encoded.extend_from_slice(&[0x00, role.as_byte(), SignalingVersion::V4.as_byte()]);
                encoded.extend_from_slice(room);
                if let Some(token) = token {
                    encoded.extend_from_slice(token);
                }
                encoded
            }
            Self::Relay(packet) => packet.clone(),
            Self::Quit => vec![0x02],
            Self::HandshakeComplete => vec![0x03],
            Self::RegisterRecovery(capability) => {
                let mut encoded = Vec::with_capacity(33);
                encoded.push(0x04);
                encoded.extend_from_slice(capability);
                encoded
            }
            Self::Resume {
                role,
                room,
                capability,
                epoch,
            } => {
                let mut encoded = Vec::with_capacity(75);
                encoded.extend_from_slice(&[0x05, role.as_byte(), SignalingVersion::V4.as_byte()]);
                encoded.extend_from_slice(room);
                encoded.extend_from_slice(capability);
                encoded.extend_from_slice(&epoch.to_be_bytes());
                encoded
            }
            Self::Burn => vec![0x06],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerPacket {
    Relay(Vec<u8>),
    PeerJoined,
    PeerQuit,
    Expired,
    Error(ErrorCode),
    Token([u8; 32]),
    HandshakeConfirmed,
    RecoveryRegistered,
    PeerResuming { epoch: u64 },
    ResumeReady { epoch: u64 },
    RoomBurned,
}

impl ServerPacket {
    pub fn parse(data: &[u8]) -> Result<Self, ParseError> {
        let Some(&opcode) = data.first() else {
            return Err(ParseError::Format);
        };

        match opcode {
            0x01 => {
                validate_relay(data)?;
                Ok(Self::Relay(data.to_vec()))
            }
            0x02 if data.len() == 1 => Ok(Self::PeerJoined),
            0x03 if data.len() == 1 => Ok(Self::PeerQuit),
            0x04 if data.len() == 1 => Ok(Self::Expired),
            0x05 if data.len() == 2 => Ok(Self::Error(ErrorCode::parse(data[1])?)),
            0x06 if data.len() == 33 => Ok(Self::Token(read_array(&data[1..])?)),
            0x07 if data.len() == 1 => Ok(Self::HandshakeConfirmed),
            0x08 if data.len() == 1 => Ok(Self::RecoveryRegistered),
            0x09 if data.len() == 9 => Ok(Self::PeerResuming {
                epoch: u64::from_be_bytes(read_array(&data[1..9])?),
            }),
            0x0a if data.len() == 9 => Ok(Self::ResumeReady {
                epoch: u64::from_be_bytes(read_array(&data[1..9])?),
            }),
            0x0b if data.len() == 1 => Ok(Self::RoomBurned),
            0x02..=0x0b => Err(ParseError::Format),
            _ => Err(ParseError::Opcode),
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::Relay(packet) => packet.clone(),
            Self::PeerJoined => vec![0x02],
            Self::PeerQuit => vec![0x03],
            Self::Expired => vec![0x04],
            Self::Error(code) => vec![0x05, *code as u8],
            Self::Token(token) => {
                let mut encoded = Vec::with_capacity(33);
                encoded.push(0x06);
                encoded.extend_from_slice(token);
                encoded
            }
            Self::HandshakeConfirmed => vec![0x07],
            Self::RecoveryRegistered => vec![0x08],
            Self::PeerResuming { epoch } => {
                let mut encoded = Vec::with_capacity(9);
                encoded.push(0x09);
                encoded.extend_from_slice(&epoch.to_be_bytes());
                encoded
            }
            Self::ResumeReady { epoch } => {
                let mut encoded = Vec::with_capacity(9);
                encoded.push(0x0a);
                encoded.extend_from_slice(&epoch.to_be_bytes());
                encoded
            }
            Self::RoomBurned => vec![0x0b],
        }
    }
}

fn validate_relay(data: &[u8]) -> Result<(), ParseError> {
    if data.len() < 3 {
        return Err(ParseError::Format);
    }
    let length = usize::from(u16::from_be_bytes([data[1], data[2]]));
    if !(1..=MAX_RELAY_FRAME).contains(&length) || length + 3 != data.len() {
        return Err(ParseError::Format);
    }
    Ok(())
}

fn read_array<const N: usize>(data: &[u8]) -> Result<[u8; N], ParseError> {
    data.try_into().map_err(|_| ParseError::Format)
}

#[cfg(test)]
mod tests {
    use super::{
        ClientPacket, ErrorCode, ParseError, Role, ServerPacket, SignalingVersion, MAX_RELAY_FRAME,
    };

    #[test]
    fn v4_join_and_resume_use_exact_lengths_and_version() {
        let room = [0x11; 32];
        let token = [0x22; 32];
        let join = ClientPacket::Join {
            role: Role::Responder,
            room,
            token: Some(token),
        };
        assert_eq!(join.encode().len(), 67);
        assert_eq!(&join.encode()[..3], &[0x00, b'r', 0x04]);

        let resume = ClientPacket::Resume {
            role: Role::Initiator,
            room,
            capability: [0x33; 32],
            epoch: 7,
        };
        assert_eq!(resume.encode().len(), 75);
        assert_eq!(&resume.encode()[..3], &[0x05, b'i', 0x04]);
    }

    #[test]
    fn v4_packet_round_trips_all_client_controls() {
        let packets = [
            ClientPacket::Join {
                role: Role::Initiator,
                room: [0x01; 32],
                token: None,
            },
            ClientPacket::Join {
                role: Role::Responder,
                room: [0x02; 32],
                token: Some([0x03; 32]),
            },
            ClientPacket::Relay(vec![0x01, 0x00, 0x01, 0xff]),
            ClientPacket::Quit,
            ClientPacket::HandshakeComplete,
            ClientPacket::RegisterRecovery([0x04; 32]),
            ClientPacket::Resume {
                role: Role::Responder,
                room: [0x05; 32],
                capability: [0x06; 32],
                epoch: u64::MAX,
            },
            ClientPacket::Burn,
        ];

        for packet in packets {
            let encoded = packet.encode();
            assert_eq!(ClientPacket::parse_v4(&encoded).unwrap(), packet);
        }
    }

    #[test]
    fn relay_accepts_one_to_maximum_payload_and_rejects_other_lengths() {
        for length in [1, MAX_RELAY_FRAME] {
            let mut encoded = vec![0x01, 0, 0];
            encoded[1..3].copy_from_slice(&(length as u16).to_be_bytes());
            encoded.extend(std::iter::repeat_n(0xaa, length));
            assert!(ClientPacket::parse_v4(&encoded).is_ok());
        }

        for length in [0, MAX_RELAY_FRAME + 1] {
            let mut encoded = vec![0x01, 0, 0];
            encoded[1..3].copy_from_slice(&(length as u16).to_be_bytes());
            encoded.extend(std::iter::repeat_n(0xaa, length));
            assert_eq!(ClientPacket::parse_v4(&encoded), Err(ParseError::Format));
        }
    }

    #[test]
    fn malformed_versions_roles_opcodes_and_trailing_bytes_are_rejected() {
        let mut wrong_version = vec![0x00, b'i', 0x03];
        wrong_version.extend_from_slice(&[0; 32]);
        assert_eq!(
            ClientPacket::parse_v4(&wrong_version),
            Err(ParseError::Version)
        );
        let mut wrong_role = vec![0x00, b'x', 0x04];
        wrong_role.extend_from_slice(&[0; 32]);
        assert_eq!(ClientPacket::parse_v4(&wrong_role), Err(ParseError::Format));
        assert_eq!(ClientPacket::parse_v4(&[0xff]), Err(ParseError::Opcode));
        assert_eq!(
            ClientPacket::parse_v4(&[0x02, 0x00]),
            Err(ParseError::Format)
        );
        assert_eq!(
            ClientPacket::parse_v4(&[0x03, 0x00]),
            Err(ParseError::Format)
        );
        let mut malformed_recovery = vec![0x04];
        malformed_recovery.extend_from_slice(&[0; 32]);
        malformed_recovery.push(0);
        assert_eq!(
            ClientPacket::parse_v4(&malformed_recovery),
            Err(ParseError::Format)
        );
        let mut trailing_resume = vec![0x05, b'i', 0x04];
        trailing_resume.extend_from_slice(&[0; 32]);
        trailing_resume.extend_from_slice(&[0; 32]);
        trailing_resume.extend_from_slice(&[0; 8]);
        trailing_resume.push(0);
        assert_eq!(
            ClientPacket::parse_v4(&trailing_resume),
            Err(ParseError::Format)
        );
        assert_eq!(ClientPacket::parse_v4(&[0x06, 0]), Err(ParseError::Format));
    }

    #[test]
    fn server_packets_round_trip_and_error_payload_is_exact() {
        let packets = [
            ServerPacket::Relay(vec![0x01, 0x00, 0x01, 0xff]),
            ServerPacket::PeerJoined,
            ServerPacket::PeerQuit,
            ServerPacket::Expired,
            ServerPacket::Error(ErrorCode::Unauthorized),
            ServerPacket::Token([0x07; 32]),
            ServerPacket::HandshakeConfirmed,
            ServerPacket::RecoveryRegistered,
            ServerPacket::PeerResuming { epoch: 8 },
            ServerPacket::ResumeReady { epoch: 9 },
            ServerPacket::RoomBurned,
        ];

        for packet in packets {
            let encoded = packet.encode();
            assert_eq!(ServerPacket::parse(&encoded).unwrap(), packet);
        }
        assert_eq!(
            ServerPacket::Error(ErrorCode::Expired).encode(),
            [0x05, 0x09]
        );
        assert_eq!(SignalingVersion::V4.as_byte(), 0x04);
    }
}
