//! WebSocket relay transport.
//!
//! Internal module for WebSocket communication with the signaling server.
//!
//! # Frame Handling Invariants
//!
//! - Strict 1:1 mapping: one WS binary message = one Frame
//! - No buffering, no message combining/splitting
//! - Each `send_frame()` = exactly one `ws.send(Binary(...))`
//! - Each `recv_frame()` = exactly one `ws.next()` → parse → Frame

use blindwire_core::frame::Frame;
use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpStream;
use tokio_tungstenite::{
    connect_async, tungstenite::protocol::Message as WsMessage, MaybeTlsStream, WebSocketStream,
};

use crate::config::Role;
use crate::error::TransportError;

/// Signaling opcodes (Client → Server).
mod opcode {
    pub const JOIN: u8 = 0x00;
    pub const RELAY: u8 = 0x01;
    /// Used by close() for graceful disconnect.
    #[allow(dead_code)]
    pub const QUIT: u8 = 0x02;
}

/// Signaling opcodes (Server → Client).
mod server_opcode {
    pub const RELAY: u8 = 0x01;
    pub const PEER_JOINED: u8 = 0x02;
    pub const PEER_QUIT: u8 = 0x03;
    pub const EXPIRED: u8 = 0x04;
    pub const ERROR: u8 = 0x05;
    pub const VERSION_MISMATCH: u8 = 0x06;
    pub const RATE_LIMIT_EXCEEDED: u8 = 0x07;
}

/// Internal WebSocket relay transport.
///
/// Does not implement `Clone` to prevent socket duplication.
pub(crate) struct RelayTransport {
    ws: WebSocketStream<MaybeTlsStream<TcpStream>>,
    /// Kept for future reconnection logic.
    #[allow(dead_code)]
    session_id: [u8; 32],
}

impl std::fmt::Debug for RelayTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RelayTransport")
            .field("session_id", &hex::encode(self.session_id))
            .finish()
    }
}

impl RelayTransport {
    /// Connect to the signaling server and join a session.
    pub async fn connect(
        url: &str,
        session_id: [u8; 32],
        role: Role,
    ) -> Result<Self, TransportError> {
        // Establish WebSocket connection
        let (ws, _response) = connect_async(url)
            .await
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;

        let mut transport = Self { ws, session_id };

        // Send JOIN message: [opcode:1][role:1][version:1][session_id:32]
        let mut join_msg = Vec::with_capacity(35);
        join_msg.push(opcode::JOIN);
        join_msg.push(role.as_byte());
        join_msg.push(0x02); // Protocol Version 2.0
        join_msg.extend_from_slice(&session_id);

        transport
            .ws
            .send(WsMessage::Binary(join_msg))
            .await
            .map_err(|e| TransportError::WebSocket(e.to_string()))?;

        Ok(transport)
    }

    /// Wait for peer to join.
    ///
    /// Returns `Ok(())` when PEER_JOINED is received.
    pub async fn wait_for_peer(&mut self) -> Result<(), TransportError> {
        loop {
            let msg = self.recv_raw().await?;
            if msg.is_empty() {
                continue;
            }

            match msg[0] {
                server_opcode::PEER_JOINED => return Ok(()),
                server_opcode::ERROR => {
                    let code = msg.get(1).copied().unwrap_or(0);
                    return Err(TransportError::UnexpectedResponse(code));
                }
                server_opcode::EXPIRED => return Err(TransportError::SessionTerminated),
                server_opcode::VERSION_MISMATCH => return Err(TransportError::VersionMismatch),
                server_opcode::RATE_LIMIT_EXCEEDED => return Err(TransportError::RateLimitExceeded),
                _ => {
                    // Ignore other messages while waiting for peer
                    continue;
                }
            }
        }
    }

    /// Send a protocol frame to the peer via relay.
    ///
    /// Wraps the frame in a RELAY envelope: [0x01][len:2][frame_bytes]
    pub async fn send_frame(&mut self, frame: Frame) -> Result<(), TransportError> {
        let wire = frame.to_wire();
        let len = wire.len() as u16;

        // RELAY envelope: [opcode:1][len:2][body:N]
        let mut envelope = Vec::with_capacity(3 + wire.len());
        envelope.push(opcode::RELAY);
        envelope.extend_from_slice(&len.to_be_bytes());
        envelope.extend_from_slice(&wire);

        self.ws
            .send(WsMessage::Binary(envelope))
            .await
            .map_err(|e| TransportError::WebSocket(e.to_string()))
    }

    /// Receive a protocol frame from the peer via relay.
    ///
    /// Unwraps the RELAY envelope and parses the frame.
    pub async fn recv_frame(&mut self) -> Result<Frame, TransportError> {
        loop {
            let msg = self.recv_raw().await?;
            if msg.is_empty() {
                continue;
            }

            match msg[0] {
                server_opcode::RELAY => {
                    // Parse frame from RELAY envelope
                    // Server relays the full envelope: [opcode:1][relay_len:2][frame_wire]
                    // frame_wire also has its own prefix: [frame_len:2][body...]
                    // We need to skip 1 + 2 + 2 = 5 bytes to reach the body (type + payload)
                    if msg.len() < 6 {
                        return Err(TransportError::Protocol(
                            blindwire_core::ProtocolError::MessageEmpty,
                        ));
                    }
                    // Skip relay header (3) + frame length prefix (2) = 5 bytes
                    return Frame::parse(&msg[5..]).map_err(TransportError::Protocol);
                }
                server_opcode::PEER_JOINED => {
                    // Peer joined while we were already waiting/active.
                    // This is expected if we connected before the peer.
                    continue;
                }
                server_opcode::PEER_QUIT => return Err(TransportError::PeerDisconnected),
                server_opcode::EXPIRED => return Err(TransportError::SessionTerminated),
                server_opcode::VERSION_MISMATCH => return Err(TransportError::VersionMismatch),
                server_opcode::RATE_LIMIT_EXCEEDED => return Err(TransportError::RateLimitExceeded),
                server_opcode::ERROR => {
                    let code = msg.get(1).copied().unwrap_or(0);
                    return Err(TransportError::UnexpectedResponse(code));
                }
                other => return Err(TransportError::UnexpectedResponse(other)),
            }
        }
    }

    /// Receive raw binary message from WebSocket.
    async fn recv_raw(&mut self) -> Result<Vec<u8>, TransportError> {
        loop {
            match self.ws.next().await {
                Some(Ok(WsMessage::Binary(data))) => return Ok(data),
                Some(Ok(WsMessage::Close(_))) => return Err(TransportError::PeerDisconnected),
                Some(Ok(_)) => continue, // Ignore Ping, Pong, Text
                Some(Err(e)) => return Err(TransportError::WebSocket(e.to_string())),
                None => return Err(TransportError::PeerDisconnected),
            }
        }
    }

    /// Send QUIT and close the connection.
    ///
    /// Reserved for explicit cleanup in future reconnection scenarios.
    #[allow(dead_code)]
    pub async fn close(&mut self) {
        // Best effort QUIT
        let _ = self.ws.send(WsMessage::Binary(vec![opcode::QUIT])).await;
        let _ = self.ws.close(None).await;
    }
}
