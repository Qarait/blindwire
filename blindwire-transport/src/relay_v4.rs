#![allow(dead_code)]

use crate::config::{Role, TransportConfig};
use crate::error::TransportError;
use crate::relay::connect_websocket;
use blindwire_core::Frame;
use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpStream;
use tokio_tungstenite::{
    tungstenite::protocol::Message as WsMessage, MaybeTlsStream, WebSocketStream,
};

const MAX_RELAY_FRAME: usize = 4096;

mod opcode {
    pub const JOIN: u8 = 0x00;
    pub const RELAY: u8 = 0x01;
    pub const QUIT: u8 = 0x02;
    pub const HANDSHAKE_COMPLETE: u8 = 0x03;
    pub const REGISTER_RECOVERY: u8 = 0x04;
    pub const RESUME: u8 = 0x05;
    pub const BURN: u8 = 0x06;
}

mod server_opcode {
    pub const RELAY: u8 = 0x01;
    pub const PEER_JOINED: u8 = 0x02;
    pub const PEER_QUIT: u8 = 0x03;
    pub const EXPIRED: u8 = 0x04;
    pub const ERROR: u8 = 0x05;
    pub const TOKEN: u8 = 0x06;
    pub const HANDSHAKE_CONFIRMED: u8 = 0x07;
    pub const RECOVERY_REGISTERED: u8 = 0x08;
    pub const PEER_RESUMING: u8 = 0x09;
    pub const RESUME_READY: u8 = 0x0a;
    pub const ROOM_BURNED: u8 = 0x0b;
}

/// Events emitted by the signaling-v4 relay.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum RelayEventV4 {
    /// An opaque Protocol 2.1 frame received from the peer.
    Frame(Frame),
    /// The peer joined the room.
    PeerJoined,
    /// The peer disconnected.
    PeerQuit,
    /// The room expired.
    Expired,
    /// The relay returned a sanitized error code.
    Error(u8),
    /// The relay confirmed both roles completed Noise.
    HandshakeConfirmed,
    /// The relay stored a recovery capability hash.
    RecoveryRegistered,
    /// The peer is resuming at the given epoch.
    PeerResuming { epoch: u64 },
    /// This role is ready to resume at the given epoch.
    ResumeReady { epoch: u64 },
    /// The relay minted an initiator token.
    Token([u8; 32]),
    /// The room was burned.
    RoomBurned,
}

/// Native WebSocket transport for signaling-v4.
pub(crate) struct RelayTransportV4 {
    ws: Option<WebSocketStream<MaybeTlsStream<TcpStream>>>,
}

impl std::fmt::Debug for RelayTransportV4 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RelayTransportV4")
            .finish_non_exhaustive()
    }
}

impl RelayTransportV4 {
    /// Connect and join a new signaling-v4 room.
    pub(crate) async fn connect_initial(
        config: &TransportConfig,
    ) -> Result<(Self, Option<[u8; 32]>), TransportError> {
        let ws = connect_websocket(config).await?;
        let mut transport = Self { ws: Some(ws) };
        transport.send_raw(encode_initial_join(config)).await?;
        match (config.role, transport.recv_event().await?) {
            (Role::Initiator, RelayEventV4::Token(token)) => Ok((transport, Some(token))),
            (Role::Responder, RelayEventV4::PeerJoined) => Ok((transport, None)),
            (_, RelayEventV4::Error(code)) => Err(server_error(code)),
            (_, event) => Err(unexpected_event(event)),
        }
    }

    /// Connect to an existing room using a stored capability and epoch.
    pub(crate) async fn connect_resume(
        config: &TransportConfig,
        capability: [u8; 32],
        epoch: u64,
    ) -> Result<Self, TransportError> {
        let ws = connect_websocket(config).await?;
        let mut transport = Self { ws: Some(ws) };
        transport
            .send_raw(encode_resume(config, capability, epoch))
            .await?;
        match transport.recv_event().await? {
            RelayEventV4::ResumeReady { .. } => Ok(transport),
            RelayEventV4::Error(code) => Err(server_error(code)),
            event => Err(unexpected_event(event)),
        }
    }

    /// Send one opaque Protocol 2.1 frame.
    pub(crate) async fn send_frame(&mut self, frame: Frame) -> Result<(), TransportError> {
        let wire = frame.to_wire();
        if wire.is_empty() || wire.len() > MAX_RELAY_FRAME {
            return Err(TransportError::Protocol(
                blindwire_core::ProtocolError::MessageTooLarge,
            ));
        }
        let length = u16::try_from(wire.len()).map_err(|_| {
            TransportError::Protocol(blindwire_core::ProtocolError::MessageTooLarge)
        })?;
        let mut packet = Vec::with_capacity(3 + wire.len());
        packet.push(opcode::RELAY);
        packet.extend_from_slice(&length.to_be_bytes());
        packet.extend_from_slice(&wire);
        self.send_raw(packet).await
    }

    /// Receive and strictly parse the next relay event.
    pub(crate) async fn recv_event(&mut self) -> Result<RelayEventV4, TransportError> {
        let packet = self.recv_raw().await?;
        parse_server_packet(&packet)
    }

    /// Tell the relay this role completed its local Noise handshake.
    pub(crate) async fn send_handshake_complete(&mut self) -> Result<(), TransportError> {
        self.send_raw(vec![opcode::HANDSHAKE_COMPLETE]).await
    }

    /// Register a fresh recovery capability with the relay.
    pub(crate) async fn register_recovery(
        &mut self,
        capability: [u8; 32],
    ) -> Result<(), TransportError> {
        let mut packet = Vec::with_capacity(33);
        packet.push(opcode::REGISTER_RECOVERY);
        packet.extend_from_slice(&capability);
        self.send_raw(packet).await
    }

    /// Ask the relay to burn the room.
    pub(crate) async fn burn(&mut self) -> Result<(), TransportError> {
        self.send_raw(vec![opcode::BURN]).await
    }

    /// Send a quit control and close the WebSocket.
    pub(crate) async fn close(&mut self) {
        if self.ws.is_some() {
            let _ = self.send_raw(vec![opcode::QUIT]).await;
            if let Some(ws) = self.ws.as_mut() {
                let _ = ws.close(None).await;
            }
        }
    }

    pub(crate) fn detach(&mut self) {
        let _ = self.ws.take();
    }

    pub(crate) fn parse_relay_packet(packet: &[u8]) -> Result<Frame, TransportError> {
        if packet.len() < 5 || packet[0] != server_opcode::RELAY {
            return Err(TransportError::UnexpectedResponse(server_opcode::RELAY));
        }
        let relay_length = usize::from(u16::from_be_bytes([packet[1], packet[2]]));
        if !(3..=MAX_RELAY_FRAME + 2).contains(&relay_length) || packet.len() != relay_length + 3 {
            return Err(TransportError::UnexpectedResponse(server_opcode::RELAY));
        }
        let frame_length = Frame::read_length(&[packet[3], packet[4]])?;
        if relay_length != frame_length + 2 {
            return Err(TransportError::UnexpectedResponse(server_opcode::RELAY));
        }
        Frame::parse(&packet[5..]).map_err(TransportError::Protocol)
    }

    async fn send_raw(&mut self, packet: Vec<u8>) -> Result<(), TransportError> {
        self.ws
            .as_mut()
            .ok_or(TransportError::SessionTerminated)?
            .send(WsMessage::Binary(packet))
            .await
            .map_err(|error| TransportError::WebSocket(error.to_string()))
    }

    async fn recv_raw(&mut self) -> Result<Vec<u8>, TransportError> {
        loop {
            let ws = self.ws.as_mut().ok_or(TransportError::SessionTerminated)?;
            match ws.next().await {
                Some(Ok(WsMessage::Binary(data))) => return Ok(data),
                Some(Ok(WsMessage::Close(_))) => return Err(TransportError::PeerDisconnected),
                Some(Ok(_)) => continue,
                Some(Err(error)) => return Err(TransportError::WebSocket(error.to_string())),
                None => return Err(TransportError::PeerDisconnected),
            }
        }
    }
}

fn encode_initial_join(config: &TransportConfig) -> Vec<u8> {
    let mut packet = Vec::with_capacity(if config.token.is_some() { 67 } else { 35 });
    packet.extend_from_slice(&[opcode::JOIN, config.role.as_byte(), 0x04]);
    packet.extend_from_slice(&config.session_id);
    if let Some(token) = config.token {
        packet.extend_from_slice(&token);
    }
    packet
}

fn encode_resume(config: &TransportConfig, capability: [u8; 32], epoch: u64) -> Vec<u8> {
    let mut packet = Vec::with_capacity(75);
    packet.extend_from_slice(&[opcode::RESUME, config.role.as_byte(), 0x04]);
    packet.extend_from_slice(&config.session_id);
    packet.extend_from_slice(&capability);
    packet.extend_from_slice(&epoch.to_be_bytes());
    packet
}

fn parse_server_packet(packet: &[u8]) -> Result<RelayEventV4, TransportError> {
    let Some(&opcode) = packet.first() else {
        return Err(TransportError::UnexpectedResponse(0));
    };
    match opcode {
        server_opcode::RELAY => {
            RelayTransportV4::parse_relay_packet(packet).map(RelayEventV4::Frame)
        }
        server_opcode::PEER_JOINED if packet.len() == 1 => Ok(RelayEventV4::PeerJoined),
        server_opcode::PEER_QUIT if packet.len() == 1 => Ok(RelayEventV4::PeerQuit),
        server_opcode::EXPIRED if packet.len() == 1 => Ok(RelayEventV4::Expired),
        server_opcode::ERROR if packet.len() == 2 => Ok(RelayEventV4::Error(packet[1])),
        server_opcode::TOKEN if packet.len() == 33 => {
            let mut token = [0_u8; 32];
            token.copy_from_slice(&packet[1..]);
            Ok(RelayEventV4::Token(token))
        }
        server_opcode::HANDSHAKE_CONFIRMED if packet.len() == 1 => {
            Ok(RelayEventV4::HandshakeConfirmed)
        }
        server_opcode::RECOVERY_REGISTERED if packet.len() == 1 => {
            Ok(RelayEventV4::RecoveryRegistered)
        }
        server_opcode::PEER_RESUMING if packet.len() == 9 => {
            Ok(RelayEventV4::PeerResuming {
                epoch: u64::from_be_bytes(packet[1..9].try_into().map_err(|_| {
                    TransportError::UnexpectedResponse(server_opcode::PEER_RESUMING)
                })?),
            })
        }
        server_opcode::RESUME_READY if packet.len() == 9 => {
            Ok(RelayEventV4::ResumeReady {
                epoch: u64::from_be_bytes(packet[1..9].try_into().map_err(|_| {
                    TransportError::UnexpectedResponse(server_opcode::RESUME_READY)
                })?),
            })
        }
        server_opcode::ROOM_BURNED if packet.len() == 1 => Ok(RelayEventV4::RoomBurned),
        known @ 0x02..=0x0b => Err(TransportError::UnexpectedResponse(known)),
        _ => Err(TransportError::UnexpectedResponse(opcode)),
    }
}

fn server_error(code: u8) -> TransportError {
    match code {
        0x04 => TransportError::RecoveryUnavailable,
        0x06 => TransportError::VersionMismatch,
        0x07 => TransportError::RateLimitExceeded,
        0x09 => TransportError::SessionTerminated,
        other => TransportError::UnexpectedResponse(other),
    }
}

fn unexpected_event(event: RelayEventV4) -> TransportError {
    let opcode = match event {
        RelayEventV4::Frame(_) => server_opcode::RELAY,
        RelayEventV4::PeerJoined => server_opcode::PEER_JOINED,
        RelayEventV4::PeerQuit => server_opcode::PEER_QUIT,
        RelayEventV4::Expired => server_opcode::EXPIRED,
        RelayEventV4::Error(code) => code,
        RelayEventV4::HandshakeConfirmed => server_opcode::HANDSHAKE_CONFIRMED,
        RelayEventV4::RecoveryRegistered => server_opcode::RECOVERY_REGISTERED,
        RelayEventV4::PeerResuming { .. } => server_opcode::PEER_RESUMING,
        RelayEventV4::ResumeReady { .. } => server_opcode::RESUME_READY,
        RelayEventV4::Token(_) => server_opcode::TOKEN,
        RelayEventV4::RoomBurned => server_opcode::ROOM_BURNED,
    };
    TransportError::UnexpectedResponse(opcode)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::{
        encode_initial_join, encode_resume, parse_server_packet, RelayEventV4, RelayTransportV4,
    };
    use crate::TransportConfig;
    use blindwire_core::Frame;

    #[test]
    fn initial_join_bytes_are_role_and_version_bound() {
        let initiator = TransportConfig::initiator("ws://localhost:8080", [0x11; 32]);
        assert_eq!(
            encode_initial_join(&initiator),
            [vec![0x00, b'i', 0x04], vec![0x11; 32]].concat()
        );

        let responder = TransportConfig::responder("ws://localhost:8080", [0x22; 32], [0x33; 32]);
        assert_eq!(
            encode_initial_join(&responder),
            [vec![0x00, b'r', 0x04], vec![0x22; 32], vec![0x33; 32]].concat()
        );
    }

    #[test]
    fn resume_bytes_include_room_capability_and_epoch() {
        let config = TransportConfig::initiator("ws://localhost:8080", [0x44; 32]);
        let encoded = encode_resume(&config, [0x55; 32], 0x0102);
        assert_eq!(encoded.len(), 75);
        assert_eq!(&encoded[..3], &[0x05, b'i', 0x04]);
        assert_eq!(&encoded[3..35], &[0x44; 32]);
        assert_eq!(&encoded[35..67], &[0x55; 32]);
        assert_eq!(
            &encoded[67..],
            &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02]
        );
    }

    #[test]
    fn relay_event_parser_rejects_length_mismatch_without_parsing_payload() {
        let malformed = vec![0x01, 0x00, 0x05, 0x00, 0x04, 0xaa];
        assert!(parse_server_packet(&malformed).is_err());
    }

    #[test]
    fn relay_event_parser_preserves_valid_frames_and_controls() {
        let frame = Frame::data(vec![0xaa, 0xbb]).unwrap();
        let wire = frame.to_wire();
        let mut packet = vec![0x01];
        packet.extend_from_slice(&(wire.len() as u16).to_be_bytes());
        packet.extend_from_slice(&wire);
        assert_eq!(
            parse_server_packet(&packet).unwrap(),
            RelayEventV4::Frame(frame)
        );
        assert_eq!(
            parse_server_packet(&[0x09, 0, 0, 0, 0, 0, 0, 0, 7]).unwrap(),
            RelayEventV4::PeerResuming { epoch: 7 }
        );
    }

    #[test]
    fn malformed_controls_and_unknown_opcodes_are_terminal_errors() {
        assert!(parse_server_packet(&[0x07, 0]).is_err());
        assert!(parse_server_packet(&[0xff]).is_err());
        assert!(RelayTransportV4::parse_relay_packet(&[0x01, 0, 0]).is_err());
    }
}
