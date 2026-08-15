use crate::protocol::{ClientPacket, ErrorCode, ParseError, Role, ServerPacket};
use crate::room::{Room, RoomError};
use dashmap::DashMap;
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::protocol::Message;
use tokio_tungstenite::WebSocketStream;

type WebSocket = WebSocketStream<TcpStream>;
type WebSocketSink = SplitSink<WebSocket, Message>;
type WebSocketStreamPart = SplitStream<WebSocket>;
type PacketSender = mpsc::Sender<Vec<u8>>;

pub(crate) type V4RoomMap = Arc<DashMap<[u8; 32], Arc<Mutex<V4RoomState>>>>;

pub(crate) struct V4RoomState {
    pub(crate) room: Room,
    pub(crate) initiator_tx: Option<PacketSender>,
    pub(crate) responder_tx: Option<PacketSender>,
}

impl V4RoomState {
    fn new(room: [u8; 32]) -> Self {
        Self {
            room: Room::new(room, crate::protocol::SignalingVersion::V4, Instant::now()),
            initiator_tx: None,
            responder_tx: None,
        }
    }
}

pub(crate) async fn handle_connection_v4(
    mut ws_tx: WebSocketSink,
    mut ws_rx: WebSocketStreamPart,
    first: Vec<u8>,
    rooms: V4RoomMap,
) -> Result<(), Box<dyn std::error::Error>> {
    let packet = match ClientPacket::parse_v4(&first) {
        Ok(packet) => packet,
        Err(error) => {
            let _ = ws_tx
                .send(Message::Binary(
                    ServerPacket::Error(parse_error_code(error)).encode(),
                ))
                .await;
            return Ok(());
        }
    };

    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(super::MAX_QUEUE_DEPTH);
    let (kill_tx, mut kill_rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        while let Some(packet) = rx.recv().await {
            let terminal = matches!(packet.first(), Some(0x04 | 0x0b));
            if ws_tx.send(Message::Binary(packet)).await.is_err() {
                break;
            }
            if terminal {
                let _ = kill_tx.send(());
                break;
            }
        }
    });

    let (room_id, role, terminal) = match packet {
        ClientPacket::Join { role, room, token } => {
            let state = if role == Role::Initiator {
                rooms
                    .entry(room)
                    .or_insert_with(|| Arc::new(Mutex::new(V4RoomState::new(room))))
                    .clone()
            } else if let Some(state) = rooms.get(&room) {
                state.value().clone()
            } else {
                queue_error(&tx, ErrorCode::Unauthorized).await;
                return Ok(());
            };

            let join_result = {
                let mut state = lock_state(&state)?;
                state
                    .room
                    .join_initial(role, token, Instant::now())
                    .map_err(map_room_error)
                    .map(|minted| {
                        set_sender(&mut state, role, Some(tx.clone()));
                        let peer = if role == Role::Responder {
                            state.initiator_tx.clone()
                        } else {
                            None
                        };
                        (minted, peer)
                    })
            };
            let (minted_token, peer) = match join_result {
                Ok(result) => result,
                Err(code) => {
                    queue_error(&tx, code).await;
                    return Ok(());
                }
            };

            if let Some(token) = minted_token {
                queue_packet(&tx, ServerPacket::Token(token)).await;
            }
            if let Some(peer) = peer {
                queue_packet(&peer, ServerPacket::PeerJoined).await;
                queue_packet(&tx, ServerPacket::PeerJoined).await;
            }
            (room, role, false)
        }
        ClientPacket::Resume {
            role,
            room,
            capability,
            epoch,
        } => {
            let Some(state) = rooms.get(&room).map(|entry| entry.value().clone()) else {
                queue_error(&tx, ErrorCode::Unauthorized).await;
                return Ok(());
            };
            let resume_result = {
                let mut state = lock_state(&state)?;
                state
                    .room
                    .begin_resume(role, capability, epoch, Instant::now())
                    .map_err(map_room_error)
                    .map(|new_epoch| {
                        set_sender(&mut state, role, Some(tx.clone()));
                        let peer = sender_for(&state, role.other());
                        (new_epoch, peer)
                    })
            };
            let (new_epoch, peer) = match resume_result {
                Ok(result) => result,
                Err(code) => {
                    queue_error(&tx, code).await;
                    return Ok(());
                }
            };
            if let Some(peer) = peer {
                queue_packet(&peer, ServerPacket::PeerResuming { epoch: new_epoch }).await;
            }
            queue_packet(&tx, ServerPacket::ResumeReady { epoch: new_epoch }).await;
            (room, role, false)
        }
        _ => {
            queue_error(&tx, ErrorCode::InvalidFormat).await;
            return Ok(());
        }
    };

    let room_state = rooms
        .get(&room_id)
        .map(|entry| entry.value().clone())
        .ok_or("v4 room disappeared after join")?;
    let mut terminal = terminal;

    loop {
        tokio::select! {
            _ = &mut kill_rx => break,
            message = ws_rx.next() => {
                let Some(Ok(Message::Binary(data))) = message else { break; };
                let packet = match ClientPacket::parse_v4(&data) {
                    Ok(packet) => packet,
                    Err(error) => {
                        queue_error(&tx, parse_error_code(error)).await;
                        break;
                    }
                };

                match packet {
                    ClientPacket::Relay(data) => {
                        let peer = {
                            let state = lock_state(&room_state)?;
                            if !is_current_sender(&state, role, &tx) {
                                None
                            } else {
                                sender_for(&state, role.other())
                            }
                        };
                        let Some(peer) = peer else {
                            queue_error(&tx, ErrorCode::Unauthorized).await;
                            break;
                        };
                        if peer.try_send(data).is_err() {
                            queue_error(&tx, ErrorCode::QueueFull).await;
                            break;
                        }
                    }
                    ClientPacket::Quit => break,
                    ClientPacket::HandshakeComplete => {
                        let confirmation = {
                            let mut state = lock_state(&room_state)?;
                            if !is_current_sender(&state, role, &tx) {
                                Err(ErrorCode::Unauthorized)
                            } else {
                                state
                                    .room
                                    .complete_handshake(role, Instant::now())
                                    .map_err(map_room_error)
                                    .map(|confirmed| {
                                        if confirmed {
                                            (state.initiator_tx.clone(), state.responder_tx.clone())
                                        } else {
                                            (None, None)
                                        }
                                    })
                            }
                        };
                        match confirmation {
                            Ok((Some(initiator), Some(responder))) => {
                                queue_packet(&initiator, ServerPacket::HandshakeConfirmed).await;
                                queue_packet(&responder, ServerPacket::HandshakeConfirmed).await;
                            }
                            Ok((_, _)) => {}
                            Err(code) => {
                                queue_error(&tx, code).await;
                                break;
                            }
                        }
                    }
                    ClientPacket::RegisterRecovery(capability) => {
                        let result = {
                            let mut state = lock_state(&room_state)?;
                            if !is_current_sender(&state, role, &tx) {
                                Err(ErrorCode::Unauthorized)
                            } else {
                                state
                                    .room
                                    .register_recovery(role, capability, Instant::now())
                                    .map_err(map_room_error)
                            }
                        };
                        match result {
                            Ok(()) => queue_packet(&tx, ServerPacket::RecoveryRegistered).await,
                            Err(code) => {
                                queue_error(&tx, code).await;
                                break;
                            }
                        }
                    }
                    ClientPacket::Burn => {
                        let peers = {
                            let mut state = lock_state(&room_state)?;
                            if !is_current_sender(&state, role, &tx) {
                                Err(ErrorCode::Unauthorized)
                            } else {
                                state
                                    .room
                                    .burn(role)
                                    .map_err(map_room_error)
                                    .map(|()| (state.initiator_tx.clone(), state.responder_tx.clone()))
                            }
                        };
                        match peers {
                            Ok((initiator, responder)) => {
                                if let Some(initiator) = initiator {
                                    queue_packet(&initiator, ServerPacket::RoomBurned).await;
                                }
                                if let Some(responder) = responder {
                                    queue_packet(&responder, ServerPacket::RoomBurned).await;
                                }
                                rooms.remove(&room_id);
                                terminal = true;
                                break;
                            }
                            Err(code) => {
                                queue_error(&tx, code).await;
                                break;
                            }
                        }
                    }
                    ClientPacket::Join { .. } | ClientPacket::Resume { .. } => {
                        queue_error(&tx, ErrorCode::InvalidFormat).await;
                        break;
                    }
                }
            }
        }
    }

    if !terminal {
        let peer = if let Some(state) = rooms.get(&room_id).map(|entry| entry.value().clone()) {
            let mut state = lock_state(&state)?;
            if is_current_sender(&state, role, &tx) {
                let was_confirmed = state.room.is_confirmed();
                set_sender(&mut state, role, None);
                state.room.detach(role, Instant::now());
                if was_confirmed {
                    None
                } else {
                    sender_for(&state, role.other())
                }
            } else {
                None
            }
        } else {
            None
        };
        if let Some(peer) = peer {
            queue_packet(&peer, ServerPacket::PeerQuit).await;
        }

        let remove_incomplete = rooms
            .get(&room_id)
            .and_then(|entry| {
                entry
                    .value()
                    .lock()
                    .ok()
                    .map(|state| !state.room.is_confirmed())
            })
            .unwrap_or(false)
            && role == Role::Initiator;
        if remove_incomplete {
            rooms.remove(&room_id);
        }
    }

    Ok(())
}

async fn queue_packet(sender: &PacketSender, packet: ServerPacket) {
    let _ = sender.send(packet.encode()).await;
}

async fn queue_error(sender: &PacketSender, code: ErrorCode) {
    queue_packet(sender, ServerPacket::Error(code)).await;
}

fn lock_state(
    state: &Arc<Mutex<V4RoomState>>,
) -> Result<std::sync::MutexGuard<'_, V4RoomState>, Box<dyn std::error::Error>> {
    state.lock().map_err(|_| "v4 room mutex poisoned".into())
}

fn sender_for(state: &V4RoomState, role: Role) -> Option<PacketSender> {
    match role {
        Role::Initiator => state.initiator_tx.clone(),
        Role::Responder => state.responder_tx.clone(),
    }
}

fn set_sender(state: &mut V4RoomState, role: Role, sender: Option<PacketSender>) {
    match role {
        Role::Initiator => state.initiator_tx = sender,
        Role::Responder => state.responder_tx = sender,
    }
}

fn is_current_sender(state: &V4RoomState, role: Role, sender: &PacketSender) -> bool {
    sender_for(state, role).is_some_and(|current| current.same_channel(sender))
}

fn parse_error_code(error: ParseError) -> ErrorCode {
    match error {
        ParseError::Format => ErrorCode::InvalidFormat,
        ParseError::Version => ErrorCode::VersionMismatch,
        ParseError::Opcode => ErrorCode::UnknownOpcode,
    }
}

fn map_room_error(error: RoomError) -> ErrorCode {
    match error {
        RoomError::RoleTaken => ErrorCode::RoleTaken,
        RoomError::Unauthorized => ErrorCode::Unauthorized,
        RoomError::Expired => ErrorCode::Expired,
        RoomError::VersionMismatch => ErrorCode::VersionMismatch,
        RoomError::Burned => ErrorCode::Unauthorized,
    }
}
