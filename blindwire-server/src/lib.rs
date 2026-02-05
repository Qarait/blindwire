use std::sync::Arc;
use std::net::IpAddr;
use std::time::Duration;
use tokio::time::Instant;
use tokio::net::{TcpStream};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::protocol::Message;
use tokio_tungstenite::accept_hdr_async;
use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};
use futures_util::{StreamExt, SinkExt};
use dashmap::DashMap;
use sha2::{Sha256, Digest};
use tokio::net::TcpListener;

// Constants from spec
const SESSION_TTL: Duration = Duration::from_secs(3600); // 1 hour
const SESSION_TTL_TEST: Duration = Duration::from_secs(2); // 2 seconds for tests

fn get_session_ttl() -> Duration {
    if std::env::var("BLINDWIRE_TEST_TTL").is_ok() { SESSION_TTL_TEST } else { SESSION_TTL }
}

fn get_cleanup_interval() -> u64 {
    if std::env::var("BLINDWIRE_TEST_TTL").is_ok() { 1 } else { 10 }
}

const RECONNECT_GRACE: Duration = Duration::from_secs(5);
const MAX_QUEUE_DEPTH: usize = 32;
const MAX_CONN_PER_IP: usize = 5;

// Packet format [Opcode:1][Length:2][Frame:N]
// Hard limit: 1 + 2 + 4096 = 4099 bytes.
const MAX_PACKET_SIZE: usize = 4099; 

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
enum Opcode {
    Join = 0x00,
    Relay = 0x01,
    PeerJoined = 0x02,
    PeerQuit = 0x03,
    Expired = 0x04,
    Error = 0x05,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
enum ErrorCode {
    RoleTaken = 0x01,
    InvalidFormat = 0x02,
    UnknownOpcode = 0x03,
    Unauthorized = 0x04,
    QueueFull = 0x05,
}

impl Opcode {
    fn from_u8(b: u8) -> Option<Self> {
        match b {
            0x00 => Some(Self::Join),
            0x01 => Some(Self::Relay),
            0x02 => Some(Self::PeerJoined),
            0x03 => Some(Self::PeerQuit),
            0x04 => Some(Self::Expired),
            0x05 => Some(Self::Error),
            _ => None,
        }
    }
}

struct Session {
    initiator_tx: Option<mpsc::Sender<Vec<u8>>>,
    responder_tx: Option<mpsc::Sender<Vec<u8>>>,
    created_at: Instant,
    last_activity: Instant,
}

type SessionMap = Arc<DashMap<String, Session>>;
type IpConnMap = Arc<DashMap<IpAddr, usize>>;

pub async fn run_server(listener: TcpListener) {
    let sessions: SessionMap = Arc::new(DashMap::new());
    let ip_conns: IpConnMap = Arc::new(DashMap::new());

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
                    && session.initiator_tx.is_none() && session.responder_tx.is_none() {
                    to_silent.push(id);
                }
            }

            // 1. Process TTL Expirations (with notification)
            for id in to_notify {
                if let Some((_, session)) = sessions_clone.remove(&id) {
                    let pkt = vec![Opcode::Expired as u8];
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
        let sessions = sessions.clone();
        let ip_conns = ip_conns.clone();
        
        let ip = peer_addr.ip();
        let current_conns = *ip_conns.entry(ip).or_insert(0);
        if current_conns >= MAX_CONN_PER_IP {
            continue;
        }
        ip_conns.entry(ip).and_modify(|c| *c += 1);

        tokio::spawn(async move {
            if let Err(_e) = handle_connection(stream, sessions, ip).await {
                // Connection closed or error
            }
            ip_conns.entry(ip).and_modify(|c| if *c > 0 { *c -= 1 });
        });
    }
}

async fn handle_connection(stream: TcpStream, sessions: SessionMap, _ip: IpAddr) -> Result<(), Box<dyn std::error::Error>> {
    let callback = |_req: &Request, response: Response| {
        Ok(response)
    };

    let ws_stream = accept_hdr_async(stream, callback).await?;
    let (mut ws_tx, mut ws_rx) = ws_stream.split();

    // 1. Wait for JOIN packet
    let session_id;
    let role_byte;

    if let Some(Ok(Message::Binary(data))) = ws_rx.next().await {
        if data.len() != 34 || data[0] != Opcode::Join as u8 {
            let _ = ws_tx.send(Message::Binary(vec![Opcode::Error as u8, ErrorCode::InvalidFormat as u8])).await;
            return Ok(());
        }
        role_byte = data[1];
        if role_byte != 0x69 && role_byte != 0x72 {
            let _ = ws_tx.send(Message::Binary(vec![Opcode::Error as u8, ErrorCode::InvalidFormat as u8])).await;
            return Ok(());
        }
        session_id = hex::encode(&data[2..34]);
    } else {
        return Ok(());
    }

    let role = if role_byte == 0x69 { 'i' } else { 'r' };

    // Register in session map
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(MAX_QUEUE_DEPTH);
    
    let (kill_tx, mut kill_rx) = tokio::sync::oneshot::channel::<()>();

    // Writer task - owns ws_tx
    let mut ws_tx = ws_tx;
    tokio::spawn(async move {
        while let Some(pkt) = rx.recv().await {
            let is_expired = pkt.get(0) == Some(&(Opcode::Expired as u8));
            if ws_tx.send(Message::Binary(pkt)).await.is_err() { break; }
            if is_expired {
                let _ = kill_tx.send(());
                break; 
            }
        }
    });

    {
        let mut session = sessions.entry(session_id.clone()).or_insert(Session {
            initiator_tx: None,
            responder_tx: None,
            created_at: Instant::now(),
            last_activity: Instant::now(),
        });
        
        session.last_activity = Instant::now();
        
        if role == 'i' {
            if session.initiator_tx.is_some() {
                let _ = tx.send(vec![Opcode::Error as u8, ErrorCode::RoleTaken as u8]).await;
                return Ok(()); 
            }
            session.initiator_tx = Some(tx.clone()); // We use clone for the loop
            if let Some(ref peer_tx) = session.responder_tx {
                let _ = peer_tx.try_send(vec![Opcode::PeerJoined as u8]);
            }
        } else {
            if session.responder_tx.is_some() {
                let _ = tx.send(vec![Opcode::Error as u8, ErrorCode::RoleTaken as u8]).await;
                return Ok(());
            }
            session.responder_tx = Some(tx.clone());
            if let Some(ref peer_tx) = session.initiator_tx {
                let _ = peer_tx.try_send(vec![Opcode::PeerJoined as u8]);
            }
        }
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
                        let opcode = match Opcode::from_u8(opcode_byte) {
                            Some(o) => o,
                            None => {
                                let _ = tx.send(vec![Opcode::Error as u8, ErrorCode::UnknownOpcode as u8]).await;
                                break;
                            }
                        };
                        
                        // Update activity
                        if let Some(mut s) = sessions.get_mut(&session_id) {
                            s.last_activity = Instant::now();
                        }

                        if opcode == Opcode::Relay {
                            // Strict binary relay validation
                            if data.len() < 3 { 
                                let _ = tx.send(vec![Opcode::Error as u8, ErrorCode::InvalidFormat as u8]).await;
                                break; 
                            }
                            let proto_len = u16::from_be_bytes([data[1], data[2]]) as usize;
                            if proto_len < 1 || proto_len > 4096 || data.len() != 3 + proto_len {
                                let _ = tx.send(vec![Opcode::Error as u8, ErrorCode::InvalidFormat as u8]).await;
                                break;
                            }

                            // Relay to peer
                            if let Some(s) = sessions.get(&session_id) {
                                let peer_tx = if role == 'i' { &s.responder_tx } else { &s.initiator_tx };
                                if let Some(ptx) = peer_tx {
                                    if ptx.try_send(data).is_err() {
                                        // Queue Full
                                        let _ = tx.send(vec![Opcode::Error as u8, ErrorCode::QueueFull as u8]).await;
                                        relay_result = Err("Queue full");
                                        break;
                                    }
                                }
                            }
                        } else if opcode == Opcode::PeerQuit || opcode_byte == 0x02 { // QUIT from client
                            break;
                        }
                    }
                    _ => break,
                }
            }
        }
    }
    // Cleanup on disconnect
    if let Some(mut s) = sessions.get_mut(&session_id) {
        if role == 'i' {
            s.initiator_tx = None;
        } else {
            s.responder_tx = None;
        }
        
        // Notify peer of our departure (Quit or Kill)
        let peer_tx = if role == 'i' { &s.responder_tx } else { &s.initiator_tx };
        if let Some(ptx) = peer_tx {
            let _ = ptx.try_send(vec![Opcode::PeerQuit as u8]);
        }
    }

    if let Err(e) = relay_result {
        return Err(e.into());
    }
    Ok(())
}

#[allow(dead_code)]
fn hash_id(id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(id);
    let result = hasher.finalize();
    hex::encode(&result[..8]) // Truncated hash for privacy purposes inside server logs if enabled
}
