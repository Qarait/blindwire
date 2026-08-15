pub mod protocol;
pub mod room;

use dashmap::{mapref::entry::Entry, DashMap};
use futures_util::{SinkExt, StreamExt};
use rand::RngCore;
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio::time::Instant;
use tokio_tungstenite::accept_hdr_async;
use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};
use tokio_tungstenite::tungstenite::protocol::Message;

// Constants from spec
const SESSION_TTL: Duration = Duration::from_secs(3600); // 1 hour
const SESSION_TTL_TEST: Duration = Duration::from_secs(2); // 2 seconds for tests

fn get_session_ttl() -> Duration {
    if std::env::var("BLINDWIRE_TEST_TTL").is_ok() {
        SESSION_TTL_TEST
    } else {
        SESSION_TTL
    }
}

fn get_cleanup_interval() -> u64 {
    if std::env::var("BLINDWIRE_TEST_TTL").is_ok() {
        1
    } else {
        10
    }
}

const RECONNECT_GRACE: Duration = Duration::from_secs(5);
const MAX_QUEUE_DEPTH: usize = 32;
const MAX_CONN_PER_IP: usize = 5;
const MAX_TOTAL_CONNECTIONS: usize = 1000;
const WEBSOCKET_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const JOIN_TIMEOUT: Duration = Duration::from_secs(10);

// Packet format [Opcode:1][Length:2][Frame:N]
// Hard limit: 1 + 2 + 4096 = 4099 bytes.
const MAX_PACKET_SIZE: usize = 4099;

/// Signaling opcodes accepted from clients.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
enum ClientOpcode {
    Join = 0x00,
    Relay = 0x01,
    Quit = 0x02,
    HandshakeComplete = 0x03,
}

/// Signaling opcodes emitted by the relay.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
enum ServerOpcode {
    Relay = 0x01,
    PeerJoined = 0x02,
    PeerQuit = 0x03,
    Expired = 0x04,
    Error = 0x05,
    Token = 0x06,
    HandshakeConfirmed = 0x07,
}

/// Fix D: Error codes for ERROR(0x05) payload
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
#[allow(dead_code)]
enum ErrorCode {
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

impl ClientOpcode {
    fn from_u8(b: u8) -> Option<Self> {
        match b {
            0x00 => Some(Self::Join),
            0x01 => Some(Self::Relay),
            0x02 => Some(Self::Quit),
            0x03 => Some(Self::HandshakeComplete),
            _ => None,
        }
    }
}

struct Session {
    initiator_tx: Option<mpsc::Sender<Vec<u8>>>,
    responder_tx: Option<mpsc::Sender<Vec<u8>>>,
    created_at: Instant,
    last_activity: Instant,
    token: Option<[u8; 32]>,
    token_state: TokenState,
    initiator_complete: bool,
    responder_complete: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TokenState {
    Available,
    Reserved,
    Consumed,
}

type SessionMap = Arc<DashMap<String, Session>>;
type IpConnMap = Arc<DashMap<IpAddr, usize>>;

fn effective_client_ip(peer_ip: IpAddr, request: &Request) -> IpAddr {
    if !peer_ip.is_loopback() {
        return peer_ip;
    }

    request
        .headers()
        .get("x-real-ip")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<IpAddr>().ok())
        .unwrap_or(peer_ip)
}

fn decrement_ip_connection(ip_conns: &DashMap<IpAddr, usize>, ip: IpAddr) {
    if let Entry::Occupied(mut entry) = ip_conns.entry(ip) {
        if *entry.get() <= 1 {
            entry.remove();
        } else {
            *entry.get_mut() -= 1;
        }
    }
}

pub async fn run_server(listener: TcpListener) {
    let sessions: SessionMap = Arc::new(DashMap::new());
    let ip_conns: IpConnMap = Arc::new(DashMap::new());
    let ip_bursts: Arc<DashMap<IpAddr, Vec<Instant>>> = Arc::new(DashMap::new());
    let total_conns = Arc::new(AtomicUsize::new(0));

    // Cleanup task
    let sessions_clone = sessions.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(get_cleanup_interval()));
        loop {
            interval.tick().await;
            let now = Instant::now();

            // Distinguish between TTL expiry and silent grace cleanup
            let mut to_notify = Vec::new();
            let mut to_silent = Vec::new();

            for entry in sessions_clone.iter() {
                let id = entry.key().clone();
                let session = entry.value();
                let age = now.duration_since(session.created_at);

                if age > get_session_ttl() {
                    to_notify.push(id);
                } else if now.duration_since(session.last_activity) > RECONNECT_GRACE
                    && session.initiator_tx.is_none()
                    && session.responder_tx.is_none()
                {
                    to_silent.push(id);
                }
            }

            // 1. Process TTL Expirations (with notification)
            for id in to_notify {
                if let Some((_, session)) = sessions_clone.remove(&id) {
                    let pkt = vec![ServerOpcode::Expired as u8];
                    if let Some(tx) = session.initiator_tx {
                        let _ = tx.try_send(pkt.clone());
                    }
                    if let Some(tx) = session.responder_tx {
                        let _ = tx.try_send(pkt);
                    }
                }
            }

            // 2. Process Grace period cleanup (silent)
            for id in to_silent {
                sessions_clone.remove(&id);
            }
        }
    });

    while let Ok((stream, peer_addr)) = listener.accept().await {
        log::debug!("[SERVER] Accepted connection from {peer_addr}");
        let sessions = sessions.clone();
        let ip_conns = ip_conns.clone();
        let ip_bursts = ip_bursts.clone();
        let total_conns = total_conns.clone();

        tokio::spawn(async move {
            let peer_ip = peer_addr.ip();
            let forwarded_ip = Arc::new(StdMutex::new(None));
            let forwarded_ip_for_callback = forwarded_ip.clone();

            let handshake = tokio::time::timeout(
                WEBSOCKET_HANDSHAKE_TIMEOUT,
                accept_hdr_async(stream, move |req: &Request, res: Response| {
                    if let Ok(mut slot) = forwarded_ip_for_callback.lock() {
                        *slot = Some(effective_client_ip(peer_ip, req));
                    }
                    Ok(res)
                }),
            )
            .await;

            match handshake {
                Ok(Ok(mut ws)) => {
                    let ip = forwarded_ip
                        .lock()
                        .ok()
                        .and_then(|guard| *guard)
                        .unwrap_or(peer_ip);
                    // Global limit check
                    if total_conns.fetch_add(1, Ordering::SeqCst) >= MAX_TOTAL_CONNECTIONS {
                        total_conns.fetch_sub(1, Ordering::SeqCst);
                        let _ = ws
                            .send(Message::Binary(vec![
                                ServerOpcode::Error as u8,
                                ErrorCode::RateLimitExceeded as u8,
                            ]))
                            .await;
                        return;
                    }

                    // IP limit check
                    {
                        let mut entry = ip_conns.entry(ip).or_insert(0);
                        if *entry >= MAX_CONN_PER_IP {
                            let _ = ws
                                .send(Message::Binary(vec![
                                    ServerOpcode::Error as u8,
                                    ErrorCode::RateLimitExceeded as u8,
                                ]))
                                .await;
                            total_conns.fetch_sub(1, Ordering::SeqCst);
                            return;
                        }
                        *entry += 1;
                    }

                    // Proceed with connection
                    let _ = handle_connection_ws(ws, sessions, ip, ip_bursts).await;

                    // Cleanup
                    decrement_ip_connection(ip_conns.as_ref(), ip);
                    total_conns.fetch_sub(1, Ordering::SeqCst);
                }
                Ok(Err(_)) | Err(_) => {
                    // Handshake failed
                }
            }
        });
    }
}

async fn handle_connection_ws(
    ws: tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>,
    sessions: SessionMap,
    ip: IpAddr,
    ip_bursts: Arc<DashMap<IpAddr, Vec<Instant>>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut ws_tx, mut ws_rx) = ws.split();

    // 1. Wait for JOIN packet
    let session_id;
    let role_byte;

    if let Ok(Some(Ok(Message::Binary(data)))) =
        tokio::time::timeout(JOIN_TIMEOUT, ws_rx.next()).await
    {
        // Burst check
        {
            let now = Instant::now();
            let mut bursts = ip_bursts.entry(ip).or_default();
            bursts.retain(|&t| now.duration_since(t) < Duration::from_secs(60));
            if bursts.len() >= 10 {
                let _ = ws_tx
                    .send(Message::Binary(vec![
                        ServerOpcode::Error as u8,
                        ErrorCode::RateLimitExceeded as u8,
                    ]))
                    .await;
                return Ok(());
            }
            bursts.push(now);
        }

        if (data.len() != 35 && data.len() != 67) || data[0] != ClientOpcode::Join as u8 {
            let error_code = ErrorCode::InvalidFormat;
            let _ = ws_tx
                .send(Message::Binary(vec![
                    ServerOpcode::Error as u8,
                    error_code as u8,
                ]))
                .await;
            return Ok(());
        }

        role_byte = data[1];
        let version_byte = data[2];

        if version_byte != 0x03 {
            let _ = ws_tx
                .send(Message::Binary(vec![
                    ServerOpcode::Error as u8,
                    ErrorCode::VersionMismatch as u8,
                ]))
                .await;
            return Ok(());
        }

        if role_byte != 0x69 && role_byte != 0x72 {
            let _ = ws_tx
                .send(Message::Binary(vec![
                    ServerOpcode::Error as u8,
                    ErrorCode::InvalidFormat as u8,
                ]))
                .await;
            return Ok(());
        }
        session_id = hex::encode(&data[3..35]);

        if role_byte == 0x72 {
            // Responder must provide token: [opcode:1][role:1][version:1][session_id:32][token:32]
            if data.len() != 67 {
                let _ = ws_tx
                    .send(Message::Binary(vec![
                        ServerOpcode::Error as u8,
                        ErrorCode::InvalidFormat as u8,
                    ]))
                    .await;
                return Ok(());
            }
            let mut t = [0u8; 32];
            t.copy_from_slice(&data[35..67]);
            let join_token = t;

            // Validate token
            if let Some(mut session) = sessions.get_mut(&session_id) {
                if session.initiator_tx.is_none()
                    || session.token_state == TokenState::Consumed
                    || session.token != Some(join_token)
                {
                    let _ = ws_tx
                        .send(Message::Binary(vec![
                            ServerOpcode::Error as u8,
                            ErrorCode::Unauthorized as u8,
                        ]))
                        .await;
                    return Ok(());
                }
                if session.token_state == TokenState::Reserved || session.responder_tx.is_some() {
                    let _ = ws_tx
                        .send(Message::Binary(vec![
                            ServerOpcode::Error as u8,
                            ErrorCode::RoleTaken as u8,
                        ]))
                        .await;
                    return Ok(());
                }
                // Check expiry (using same TTL as session for simplicity, but server-side)
                if Instant::now().duration_since(session.created_at) > get_session_ttl() {
                    let _ = ws_tx
                        .send(Message::Binary(vec![
                            ServerOpcode::Error as u8,
                            ErrorCode::Expired as u8,
                        ]))
                        .await;
                    return Ok(());
                }
                session.token_state = TokenState::Reserved;
                session.initiator_complete = false;
                session.responder_complete = false;
            } else {
                // Room doesn't exist
                let _ = ws_tx
                    .send(Message::Binary(vec![
                        ServerOpcode::Error as u8,
                        ErrorCode::Unauthorized as u8,
                    ]))
                    .await;
                return Ok(());
            }
        }
    } else {
        return Ok(());
    }

    let role = if role_byte == 0x69 { 'i' } else { 'r' };
    log::debug!("[SERVER] Processing JOIN for role {role}");

    // Register in session map
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(MAX_QUEUE_DEPTH);

    let (kill_tx, mut kill_rx) = tokio::sync::oneshot::channel::<()>();

    // Writer task - owns ws_tx
    let mut ws_tx = ws_tx;
    tokio::spawn(async move {
        while let Some(pkt) = rx.recv().await {
            let is_expired = pkt.first() == Some(&(ServerOpcode::Expired as u8));
            if ws_tx.send(Message::Binary(pkt)).await.is_err() {
                break;
            }
            if is_expired {
                let _ = kill_tx.send(());
                break;
            }
        }
    });

    if role == 'i' {
        let mut session = sessions.entry(session_id.clone()).or_insert(Session {
            initiator_tx: None,
            responder_tx: None,
            created_at: Instant::now(),
            last_activity: Instant::now(),
            token: None,
            token_state: TokenState::Available,
            initiator_complete: false,
            responder_complete: false,
        });
        if session.token.is_some() || session.initiator_tx.is_some() {
            let _ = tx.try_send(vec![ServerOpcode::Error as u8, ErrorCode::RoleTaken as u8]);
            return Ok(());
        }

        let mut token = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut token);
        session.last_activity = Instant::now();
        session.token = Some(token);
        session.token_state = TokenState::Available;
        session.initiator_complete = false;
        session.responder_complete = false;
        session.initiator_tx = Some(tx.clone());

        let mut token_packet = Vec::with_capacity(33);
        token_packet.push(ServerOpcode::Token as u8);
        token_packet.extend_from_slice(&token);
        let _ = tx.try_send(token_packet);
    } else {
        let Some(mut session) = sessions.get_mut(&session_id) else {
            let _ = tx.try_send(vec![
                ServerOpcode::Error as u8,
                ErrorCode::Unauthorized as u8,
            ]);
            return Ok(());
        };
        if session.initiator_tx.is_none() || session.token_state != TokenState::Reserved {
            let _ = tx.try_send(vec![
                ServerOpcode::Error as u8,
                ErrorCode::Unauthorized as u8,
            ]);
            return Ok(());
        }
        if session.responder_tx.is_some() {
            let _ = tx.try_send(vec![ServerOpcode::Error as u8, ErrorCode::RoleTaken as u8]);
            return Ok(());
        }

        session.last_activity = Instant::now();
        session.responder_tx = Some(tx.clone());
        if let Some(peer) = &session.initiator_tx {
            let _ = peer.try_send(vec![ServerOpcode::PeerJoined as u8]);
        }
        let _ = tx.try_send(vec![ServerOpcode::PeerJoined as u8]);
    }

    // Relay loop
    let mut relay_result = Ok(());

    loop {
        tokio::select! {
            _ = &mut kill_rx => break,
            msg = ws_rx.next() => {
                match msg {
                    Some(Ok(Message::Binary(data))) => {
                        if data.is_empty() { break; }

                        let opcode_byte = data[0];
                        let opcode = match ClientOpcode::from_u8(opcode_byte) {
                            Some(o) => o,
                            None => {
                                let _ = tx.send(vec![ServerOpcode::Error as u8, ErrorCode::UnknownOpcode as u8]).await;
                                break;
                            }
                        };

                        // Update activity
                        if let Some(mut s) = sessions.get_mut(&session_id) {
                            s.last_activity = Instant::now();
                        }

                        match opcode {
                        ClientOpcode::Relay => {
                            debug_assert_eq!(opcode_byte, ServerOpcode::Relay as u8);
                            // Strict binary relay validation
                            if data.len() < 3 {
                                let _ = tx.send(vec![ServerOpcode::Error as u8, ErrorCode::InvalidFormat as u8]).await;
                                break;
                            }
                            let proto_len = u16::from_be_bytes([data[1], data[2]]) as usize;
                            if !(1..=(MAX_PACKET_SIZE - 3)).contains(&proto_len) || data.len() != 3 + proto_len {
                                let _ = tx.send(vec![ServerOpcode::Error as u8, ErrorCode::InvalidFormat as u8]).await;
                                break;
                            }

                            log::trace!("[SERVER] RELAY from {} (size: {})", role, data.len());

                            // Relay to peer
                            if let Some(s) = sessions.get_mut(&session_id) {
                                let peer_tx = if role == 'i' { &s.responder_tx } else { &s.initiator_tx };
                                if let Some(ptx) = peer_tx {
                                    if ptx.try_send(data).is_err() {
                                        // Queue Full
                                        let _ = tx.send(vec![ServerOpcode::Error as u8, ErrorCode::QueueFull as u8]).await;
                                        relay_result = Err("Queue full");
                                        break;
                                    }
                                }
                            }
                        }
                        ClientOpcode::Quit => {
                            if data.len() != 1 {
                                let _ = tx.send(vec![ServerOpcode::Error as u8, ErrorCode::InvalidFormat as u8]).await;
                            }
                            break;
                        }
                        ClientOpcode::HandshakeComplete => {
                            if data.len() != 1 {
                                let _ = tx.send(vec![ServerOpcode::Error as u8, ErrorCode::InvalidFormat as u8]).await;
                                break;
                            }

                            let mut valid = false;
                            let mut confirm = None;
                            if let Some(mut s) = sessions.get_mut(&session_id) {
                                let registered = if role == 'i' {
                                    s.initiator_tx.as_ref()
                                } else {
                                    s.responder_tx.as_ref()
                                };
                                if registered.is_some_and(|current| current.same_channel(&tx)) {
                                    match s.token_state {
                                        TokenState::Reserved => {
                                            valid = true;
                                            if role == 'i' {
                                                s.initiator_complete = true;
                                            } else {
                                                s.responder_complete = true;
                                            }
                                            if s.initiator_complete && s.responder_complete {
                                                s.token_state = TokenState::Consumed;
                                                confirm = Some((s.initiator_tx.clone(), s.responder_tx.clone()));
                                            }
                                        }
                                        TokenState::Consumed => valid = true,
                                        TokenState::Available => {}
                                    }
                                }
                            }

                            if !valid {
                                let _ = tx.send(vec![ServerOpcode::Error as u8, ErrorCode::Unauthorized as u8]).await;
                                break;
                            }
                            if let Some((Some(initiator), Some(responder))) = confirm {
                                let packet = vec![ServerOpcode::HandshakeConfirmed as u8];
                                let _ = initiator.try_send(packet.clone());
                                let _ = responder.try_send(packet);
                            }
                        }
                        ClientOpcode::Join => {
                            let _ = tx.send(vec![ServerOpcode::Error as u8, ErrorCode::UnknownOpcode as u8]).await;
                            break;
                        }
                        }
                    }
                    _ => break,
                }
            }
        }
    }
    // Cleanup on disconnect
    let mut remove_incomplete_room = false;
    if let Some(mut s) = sessions.get_mut(&session_id) {
        let registered = if role == 'i' {
            s.initiator_tx.as_ref()
        } else {
            s.responder_tx.as_ref()
        };
        if registered.is_some_and(|current| current.same_channel(&tx)) {
            if role == 'i' {
                s.initiator_tx = None;
                if let Some(peer) = &s.responder_tx {
                    let _ = peer.try_send(vec![ServerOpcode::PeerQuit as u8]);
                }
                remove_incomplete_room = s.token_state != TokenState::Consumed;
            } else {
                s.responder_tx = None;
                if s.token_state == TokenState::Reserved {
                    s.token_state = TokenState::Available;
                    s.initiator_complete = false;
                    s.responder_complete = false;
                }
                if let Some(peer) = &s.initiator_tx {
                    let _ = peer.try_send(vec![ServerOpcode::PeerQuit as u8]);
                }
            }
        }
    }
    if remove_incomplete_room {
        sessions.remove(&session_id);
    }

    if let Err(e) = relay_result {
        return Err(e.into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_reverse_proxy_may_supply_client_ip() {
        let request = Request::builder()
            .header("x-real-ip", "203.0.113.42")
            .body(())
            .unwrap();

        assert_eq!(
            effective_client_ip("127.0.0.1".parse().unwrap(), &request),
            "203.0.113.42".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn remote_client_cannot_spoof_forwarded_ip() {
        let request = Request::builder()
            .header("x-real-ip", "203.0.113.42")
            .body(())
            .unwrap();
        let peer = "198.51.100.7".parse::<IpAddr>().unwrap();

        assert_eq!(effective_client_ip(peer, &request), peer);
    }

    #[test]
    fn final_ip_connection_decrement_removes_entry() {
        let counts = DashMap::new();
        let ip = "127.0.0.1".parse().unwrap();
        counts.insert(ip, 2);

        decrement_ip_connection(&counts, ip);
        assert_eq!(counts.get(&ip).map(|count| *count), Some(1));

        decrement_ip_connection(&counts, ip);
        assert!(!counts.contains_key(&ip));

        decrement_ip_connection(&counts, ip);
        assert!(!counts.contains_key(&ip));
    }
}
