//! WebSocket relay transport.
//!
//! Internal module for WebSocket communication with the signaling server.
//!
//! # Frame Handling Invariants
//!
//! - Strict 1:1 mapping: one WS binary message = one Frame
//! - No buffering, no message combining/splitting
//! - Each `send_frame()` = exactly one `ws.send(Binary(...))`
//! - Each `recv_frame()` = exactly one `ws.next()` -> parse -> Frame

use crate::config::TransportConfig;
use crate::error::TransportError;
use crate::pinning::{BlindWireVerifier, DiskPinStore, OFFICIAL_RELAY_HOST};
use blindwire_core::frame::Frame;
use futures_util::{SinkExt, StreamExt};
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_tungstenite::{
    connect_async_tls_with_config, tungstenite::protocol::Message as WsMessage, Connector,
    MaybeTlsStream, WebSocketStream,
};

mod opcode {
    pub const JOIN: u8 = 0x00;
    pub const RELAY: u8 = 0x01;
    pub const QUIT: u8 = 0x02;
    pub const HANDSHAKE_COMPLETE: u8 = 0x03;
}

mod server_opcode {
    pub const RELAY: u8 = 0x01;
    pub const PEER_JOINED: u8 = 0x02;
    pub const PEER_QUIT: u8 = 0x03;
    pub const EXPIRED: u8 = 0x04;
    pub const ERROR: u8 = 0x05;
    pub const TOKEN: u8 = 0x06;
    pub const HANDSHAKE_CONFIRMED: u8 = 0x07;
}

mod error_code {
    pub const VERSION_MISMATCH: u8 = 0x06;
    pub const RATE_LIMIT_EXCEEDED: u8 = 0x07;
}

/// Internal WebSocket relay transport.
///
/// Does not implement `Clone` to prevent socket duplication.
pub(crate) struct RelayTransport {
    ws: WebSocketStream<MaybeTlsStream<TcpStream>>,
}

impl std::fmt::Debug for RelayTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RelayTransport").finish_non_exhaustive()
    }
}

impl RelayTransport {
    /// Connect to the signaling server and join a session.
    pub async fn connect(
        config: &TransportConfig,
    ) -> Result<(Self, Option<[u8; 32]>), TransportError> {
        let url = &config.signaling_url;
        let session_id = config.session_id;

        let pins_path = config
            .pins_path
            .clone()
            .unwrap_or_else(|| std::env::temp_dir().join("blindwire_pins.txt"));
        let store = Arc::new(DiskPinStore::new(pins_path));

        let crypto_provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let standard_verifier = rustls::client::WebPkiServerVerifier::builder_with_provider(
            Arc::new(roots),
            Arc::clone(&crypto_provider),
        )
        .build()
        .map_err(|error| TransportError::ConnectionFailed(error.to_string()))?;
        let verifier: Arc<dyn rustls::client::danger::ServerCertVerifier> = Arc::new(
            BlindWireVerifier::new(OFFICIAL_RELAY_HOST, store, standard_verifier)
                .with_expected_pin(config.expected_server_pin),
        );

        let config_tls = rustls::ClientConfig::builder_with_provider(crypto_provider)
            .with_safe_default_protocol_versions()
            .map_err(|error| TransportError::ConnectionFailed(error.to_string()))?
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();
        let connector = Connector::Rustls(Arc::new(config_tls));

        let (ws, _response) = connect_async_tls_with_config(url, None, false, Some(connector))
            .await
            .map_err(|error| match error {
                tokio_tungstenite::tungstenite::Error::Tls(_) => {
                    TransportError::TlsValidationFailed
                }
                other => TransportError::ConnectionFailed(other.to_string()),
            })?;

        let mut transport = Self { ws };
        let mut join_msg = Vec::with_capacity(if config.token.is_some() { 67 } else { 35 });
        join_msg.push(opcode::JOIN);
        join_msg.push(config.role.as_byte());
        join_msg.push(0x03);
        join_msg.extend_from_slice(&session_id);
        if let Some(token) = config.token {
            join_msg.extend_from_slice(&token);
        }
        transport
            .ws
            .send(WsMessage::Binary(join_msg))
            .await
            .map_err(|error| TransportError::WebSocket(error.to_string()))?;

        let mut token = None;
        match config.role {
            crate::config::Role::Initiator => {
                let packet = transport.recv_raw().await?;
                if packet.len() == 33 && packet[0] == server_opcode::TOKEN {
                    let mut minted = [0u8; 32];
                    minted.copy_from_slice(&packet[1..]);
                    token = Some(minted);
                } else if packet.first() == Some(&server_opcode::ERROR) {
                    return Err(Self::server_error(&packet));
                } else {
                    return Err(TransportError::UnexpectedResponse(
                        packet.first().copied().unwrap_or(0),
                    ));
                }
            }
            crate::config::Role::Responder => {
                let packet = transport.recv_raw().await?;
                match packet.first().copied() {
                    Some(server_opcode::PEER_JOINED) if packet.len() == 1 => {}
                    Some(server_opcode::ERROR) => return Err(Self::server_error(&packet)),
                    Some(other) => return Err(TransportError::UnexpectedResponse(other)),
                    None => return Err(TransportError::UnexpectedResponse(0)),
                }
            }
        }

        Ok((transport, token))
    }

    /// Wait for a responder to join an initiator's room.
    pub async fn wait_for_peer(&mut self) -> Result<(), TransportError> {
        let packet = self.recv_raw().await?;
        match packet.first().copied() {
            Some(server_opcode::PEER_JOINED) if packet.len() == 1 => Ok(()),
            Some(server_opcode::PEER_QUIT) if packet.len() == 1 => {
                Err(TransportError::PeerDisconnected)
            }
            Some(server_opcode::ERROR) => Err(Self::server_error(&packet)),
            Some(server_opcode::EXPIRED) if packet.len() == 1 => {
                Err(TransportError::SessionTerminated)
            }
            Some(other) => Err(TransportError::UnexpectedResponse(other)),
            None => Err(TransportError::UnexpectedResponse(0)),
        }
    }

    /// Send a protocol frame to the peer via the opaque relay.
    pub async fn send_frame(&mut self, frame: Frame) -> Result<(), TransportError> {
        let wire = frame.to_wire();
        let len = u16::try_from(wire.len()).map_err(|_| {
            TransportError::Protocol(blindwire_core::ProtocolError::MessageTooLarge)
        })?;
        let mut envelope = Vec::with_capacity(3 + wire.len());
        envelope.push(opcode::RELAY);
        envelope.extend_from_slice(&len.to_be_bytes());
        envelope.extend_from_slice(&wire);

        self.ws
            .send(WsMessage::Binary(envelope))
            .await
            .map_err(|error| TransportError::WebSocket(error.to_string()))
    }

    /// Receive and strictly validate one relayed protocol frame.
    pub async fn recv_frame(&mut self) -> Result<Frame, TransportError> {
        loop {
            let packet = self.recv_raw().await?;
            match packet.first().copied() {
                Some(server_opcode::RELAY) => return Self::parse_relay_packet(&packet),
                Some(server_opcode::PEER_JOINED) if packet.len() == 1 => continue,
                Some(server_opcode::PEER_QUIT) if packet.len() == 1 => {
                    return Err(TransportError::PeerDisconnected)
                }
                Some(server_opcode::EXPIRED) if packet.len() == 1 => {
                    return Err(TransportError::SessionTerminated)
                }
                Some(server_opcode::ERROR) => return Err(Self::server_error(&packet)),
                Some(other) => return Err(TransportError::UnexpectedResponse(other)),
                None => return Err(TransportError::UnexpectedResponse(0)),
            }
        }
    }

    /// Tell the relay this role reached local Noise `Active` state.
    pub async fn send_handshake_complete(&mut self) -> Result<(), TransportError> {
        self.ws
            .send(WsMessage::Binary(vec![opcode::HANDSHAKE_COMPLETE]))
            .await
            .map_err(|error| TransportError::WebSocket(error.to_string()))
    }

    /// Wait until the relay confirms both role-bound clients completed Noise.
    pub async fn wait_handshake_confirmed(&mut self) -> Result<(), TransportError> {
        loop {
            let packet = self.recv_raw().await?;
            match packet.first().copied() {
                Some(server_opcode::HANDSHAKE_CONFIRMED) if packet.len() == 1 => return Ok(()),
                Some(server_opcode::PEER_JOINED) if packet.len() == 1 => continue,
                Some(server_opcode::PEER_QUIT) if packet.len() == 1 => {
                    return Err(TransportError::PeerDisconnected)
                }
                Some(server_opcode::EXPIRED) if packet.len() == 1 => {
                    return Err(TransportError::SessionTerminated)
                }
                Some(server_opcode::ERROR) => return Err(Self::server_error(&packet)),
                Some(other) => return Err(TransportError::UnexpectedResponse(other)),
                None => return Err(TransportError::UnexpectedResponse(0)),
            }
        }
    }

    fn parse_relay_packet(packet: &[u8]) -> Result<Frame, TransportError> {
        if packet.len() < 6 {
            return Err(TransportError::UnexpectedResponse(server_opcode::RELAY));
        }
        let relay_len = u16::from_be_bytes([packet[1], packet[2]]) as usize;
        if relay_len < 3 || packet.len() != relay_len + 3 {
            return Err(TransportError::UnexpectedResponse(server_opcode::RELAY));
        }
        let frame_len = Frame::read_length(&[packet[3], packet[4]])?;
        if relay_len != frame_len + 2 {
            return Err(TransportError::UnexpectedResponse(server_opcode::RELAY));
        }
        Frame::parse(&packet[5..]).map_err(TransportError::Protocol)
    }

    fn server_error(packet: &[u8]) -> TransportError {
        if packet.len() != 2 {
            return TransportError::UnexpectedResponse(server_opcode::ERROR);
        }
        match packet[1] {
            error_code::VERSION_MISMATCH => TransportError::VersionMismatch,
            error_code::RATE_LIMIT_EXCEEDED => TransportError::RateLimitExceeded,
            code => TransportError::UnexpectedResponse(code),
        }
    }

    async fn recv_raw(&mut self) -> Result<Vec<u8>, TransportError> {
        loop {
            match self.ws.next().await {
                Some(Ok(WsMessage::Binary(data))) => return Ok(data),
                Some(Ok(WsMessage::Close(_))) => return Err(TransportError::PeerDisconnected),
                Some(Ok(_)) => continue,
                Some(Err(error)) => return Err(TransportError::WebSocket(error.to_string())),
                None => return Err(TransportError::PeerDisconnected),
            }
        }
    }

    #[allow(dead_code)]
    pub async fn close(&mut self) {
        let _ = self.ws.send(WsMessage::Binary(vec![opcode::QUIT])).await;
        let _ = self.ws.close(None).await;
    }
}
