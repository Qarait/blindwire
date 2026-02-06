use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use crossterm::{
    cursor,
    event::{self, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, Clear, ClearType},
};
use futures_util::{SinkExt, StreamExt};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use rustls_pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    DigitallySignedStruct, SignatureScheme,
};
use std::collections::HashMap;
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use rustls::ClientConfig;
use tokio_tungstenite::client_async_tls_with_config;
use tokio_tungstenite::Connector;
use tokio_tungstenite::tungstenite::protocol::Message;

use blindwire_core::frame::{Frame, LENGTH_PREFIX_SIZE};
use blindwire_core::state::{Session, SessionReceiveResult, SessionState};
use blindwire_core::ProtocolError;

const DEFAULT_SERVER: &str = "ws://127.0.0.1:8080";
const RECONNECT_DELAY: Duration = Duration::from_secs(1);

#[derive(Debug)]
struct Config {
    server_url: String,
    session_id: String,
    role: char,
    #[allow(dead_code)]
    insecure: bool,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Opcode {
    Join = 0x00,
    Relay = 0x01,
    PeerJoined = 0x02,
    PeerQuit = 0x03,
    Expired = 0x04,
    Error = 0x05,
    VersionMismatch = 0x06,
    RateLimitExceeded = 0x07,
    PinRequired = 0x08,
}

impl TryFrom<u8> for Opcode {
    type Error = ();

    fn try_from(v: u8) -> Result<Self, <Self as TryFrom<u8>>::Error> {
        match v {
            0x00 => Ok(Opcode::Join),
            0x01 => Ok(Opcode::Relay),
            0x02 => Ok(Opcode::PeerJoined),
            0x03 => Ok(Opcode::PeerQuit),
            0x04 => Ok(Opcode::Expired),
            0x05 => Ok(Opcode::Error),
            0x06 => Ok(Opcode::VersionMismatch),
            0x07 => Ok(Opcode::RateLimitExceeded),
            0x08 => Ok(Opcode::PinRequired),
            _ => Err(()),
        }
    }
}

enum AppEvent {
    Connected,
    Disconnected,
    MessageReceived(Vec<u8>),
    SecurityViolation(String),
    Notice(String),
}

#[derive(Serialize, Deserialize, Default, Debug)]
struct PinStore {
    pins: HashMap<String, String>,
}

impl PinStore {
    fn load() -> Self {
        let path = Self::path();
        if let Ok(data) = fs::read_to_string(path) {
            serde_json::from_str(&data).unwrap_or_default()
        } else {
            Self::default()
        }
    }

    fn save(&self) {
        let path = Self::path();
        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        if let Ok(data) = serde_json::to_string_pretty(self) {
            let _ = fs::write(path, data);
        }
    }

    fn path() -> PathBuf {
        let mut p = dirs_next::config_dir().unwrap_or_else(|| PathBuf::from("."));
        p.push("blindwire");
        p.push("pins.json");
        p
    }
}

#[derive(Debug)]
struct Pinner {
    pin_key: String,
    store: Arc<std::sync::Mutex<PinStore>>,
    event_tx: mpsc::Sender<AppEvent>,
}

impl ServerCertVerifier for Pinner {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let mut hasher = Sha256::new();
        hasher.update(end_entity.as_ref());
        let hash = hex::encode(hasher.finalize());

        let mut store = self.store.lock().unwrap();
        if let Some(pinned) = store.pins.get(&self.pin_key) {
            if pinned != &hash {
                let msg = format!(
                    "SECURITY VIOLATION: Relay certificate for {} has changed!\nStored: {}\nCurrent: {}",
                    self.pin_key, pinned, hash
                );
                let _ = self.event_tx.try_send(AppEvent::SecurityViolation(msg));
                return Err(rustls::Error::InvalidCertificate(
                    rustls::CertificateError::ApplicationVerificationFailure,
                ));
            }
        } else {
            // TOFU: Trust On First Use
            store.pins.insert(self.pin_key.clone(), hash.clone());
            store.save();
            let _ = self.event_tx.try_send(AppEvent::Notice(format!(
                "TOFU: Pinned new certificate for {}: {}",
                self.pin_key, hash
            )));
        }

        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

struct App {
    session: Session,
    log: Vec<String>,
    input: String,
    config: Config,
    status: String,
    last_draw: Instant,
    qr_code: Option<Vec<String>>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();

    let mut insecure = false;
    let mut server_url = DEFAULT_SERVER.to_string();
    let mut session_id = String::new();
    let mut role = 'i';

    // Minimal arg parsing
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--insecure-dev" => insecure = true,
            "--server" if i + 1 < args.len() => {
                server_url = args[i + 1].clone();
                i += 1;
            }
            "--session" if i + 1 < args.len() => {
                session_id = args[i + 1].clone();
                role = 'r'; // Providing a session implies joining as responder
                i += 1;
            }
            "--uri" if i + 1 < args.len() => {
                let uri_str = &args[i + 1];
                if let Ok(parsed) = url::Url::parse(uri_str) {
                    if parsed.scheme() == "blindwire" {
                        let host = parsed.host_str().unwrap_or("localhost");
                        let port = parsed.port_or_known_default().unwrap_or(80);
                        let path_segments: Vec<&str> =
                            parsed.path_segments().map(|c| c.collect()).unwrap_or_default();

                        if path_segments.len() >= 2 {
                            let raw_id = path_segments[0];
                            // Sanity check: Session ID must look like a base64 string
                            if raw_id.len() >= 20 {
                                session_id = raw_id.to_string();
                                role = path_segments[1].chars().next().unwrap_or('r');

                                let scheme = if host == "localhost" || host == "127.0.0.1" {
                                    "ws"
                                } else {
                                    "wss"
                                };
                                server_url = format!("{}://{}:{}", scheme, host, port);
                            }
                        }
                    }
                }
                i += 1;
            }
            _ if session_id.is_empty() => {
                session_id = args[i].clone();
                role = 'r';
            }
            _ => {}
        }
        i += 1;
    }

    if session_id.is_empty() && role == 'i' {
        // Initiator: Generate 32-byte ID
        let mut id_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut id_bytes);
        session_id = URL_SAFE_NO_PAD.encode(id_bytes);
    }

    // Transport safety check
    let is_local = server_url.contains("127.0.0.1") || server_url.contains("localhost");

    if server_url.starts_with("ws://") {
        if !is_local {
            eprintln!("ERROR: ws:// is FORBIDDEN for non-local hosts. wss:// is mandatory.");
            return Ok(());
        }
        if !insecure {
            eprintln!("ERROR: ws:// requires --insecure-dev flag.");
            return Ok(());
        }
        println!("NOTICE: Local development mode: TLS disabled.");
    }

    let config = Config {
        server_url,
        session_id,
        role,
        insecure,
    };

    let session = if config.role == 'i' {
        Session::new_initiator()?
    } else {
        Session::new_responder()?
    };

    let mut app = App {
        session,
        log: Vec::new(),
        input: String::new(),
        config,
        status: "Starting...".to_string(),
        last_draw: Instant::now(),
        qr_code: None,
    };

    app.qr_code = app.generate_qr();

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, Clear(ClearType::All), cursor::Hide)?;

    if let Err(e) = app.run().await {
        app.log.push(format!("Error: {}", e));
    }

    disable_raw_mode()?;
    execute!(stdout, cursor::Show)?;
    println!("\nSession ended.");
    Ok(())
}

impl App {
    fn generate_qr(&self) -> Option<Vec<String>> {
        if self.config.role != 'i' {
            return None;
        }

        use qrcodegen::{QrCode, QrCodeEcc};

        let url = url::Url::parse(&self.config.server_url).ok()?;
        let host = url.host_str()?;
        let port = url.port_or_known_default().unwrap_or(if url.scheme() == "wss" { 443 } else { 80 });
        let uri = format!(
            "blindwire://{}:{}/{}/r",
            host, port, self.config.session_id
        );

        let qr = QrCode::encode_text(&uri, QrCodeEcc::Low).ok()?;
        let mut lines = Vec::new();
        let size = qr.size();

        // Compact QR using half-blocks
        for y in (0..size).step_by(2) {
            let mut line = String::new();
            for x in 0..size {
                let top = qr.get_module(x, y);
                let bottom = if y + 1 < size {
                    qr.get_module(x, y + 1)
                } else {
                    false
                };

                match (top, bottom) {
                    (true, true) => line.push('█'),
                    (true, false) => line.push('▀'),
                    (false, true) => line.push('▄'),
                    (false, false) => line.push(' '),
                }
            }
            lines.push(line);
        }
        Some(lines)
    }

    async fn run(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let (event_tx, mut event_rx) = mpsc::channel::<AppEvent>(32);
        let (net_tx, mut net_rx) = mpsc::channel::<Vec<u8>>(32);

        let server_url = self.config.server_url.clone();
        let session_id = self.config.session_id.clone();
        let role = self.config.role;

        let store = Arc::new(std::sync::Mutex::new(PinStore::load()));
        let etx = event_tx.clone();

        // Networking thread
        tokio::spawn(async move {
            let url = url::Url::parse(&server_url).expect("Invalid server URL");
            let host = url.host_str().expect("No host in URL").to_string();
            let is_tls = url.scheme() == "wss";

            loop {
                let port = url.port_or_known_default().unwrap_or(if is_tls { 443 } else { 80 });
                let pin_key = format!("{}://{}:{}", url.scheme(), host, port);

                let connector = if is_tls {
                    let mut config = ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                        .with_safe_default_protocol_versions()
                        .unwrap()
                        .dangerous()
                        .with_custom_certificate_verifier(Arc::new(Pinner {
                            pin_key: pin_key.clone(),
                            store: store.clone(),
                            event_tx: etx.clone(),
                        }))
                        .with_no_client_auth();
                    
                    config.alpn_protocols = vec![b"http/1.1".to_vec()];
                    Some(Connector::Rustls(Arc::new(config)))
                } else {
                    None
                };

                let stream_res = tokio::net::TcpStream::connect(format!(
                    "{}:{}",
                    url.host_str().unwrap(),
                    port
                ))
                .await;

                if let Ok(stream) = stream_res {
                    let ws_res = client_async_tls_with_config(
                        &server_url,
                        stream,
                        None,
                        connector,
                    )
                    .await;

                    if let Ok((mut ws_stream, _)) = ws_res {
                        // Send JOIN
                        let role_byte = if role == 'i' { 0x69u8 } else { 0x72u8 };
                        let version_byte = 0x02u8; // Protocol v2.0
                        let mut join_packet = vec![Opcode::Join as u8, role_byte, version_byte];
                        let decoded_id = URL_SAFE_NO_PAD
                            .decode(&session_id)
                            .unwrap_or_else(|_| vec![0u8; 16]);
                        
                        let mut id_32 = [0u8; 32];
                        if decoded_id.len() >= 32 {
                            id_32.copy_from_slice(&decoded_id[..32]);
                        } else {
                            id_32[..decoded_id.len()].copy_from_slice(&decoded_id);
                        }
                        join_packet.extend_from_slice(&id_32);

                        if ws_stream.send(Message::Binary(join_packet)).await.is_ok() {
                            let _ = etx.send(AppEvent::Connected).await;
                            let (mut ws_tx, mut ws_rx) = ws_stream.split();

                            loop {
                                tokio::select! {
                                    Some(data) = net_rx.recv() => {
                                        if ws_tx.send(Message::Binary(data)).await.is_err() { break; }
                                    }
                                    msg = ws_rx.next() => {
                                        match msg {
                                            Some(Ok(Message::Binary(data))) => {
                                                let _ = etx.send(AppEvent::MessageReceived(data)).await;
                                            }
                                            _ => break,
                                        }
                                    }
                                }
                            }
                        }
                        let _ = etx.send(AppEvent::Disconnected).await;
                    }
                }
                tokio::time::sleep(RECONNECT_DELAY).await;
            }
        });

        self.log.push(format!("Server: {}", self.config.server_url));
        self.log
            .push(format!("Session: {}", self.config.session_id));
        if self.config.role == 'i' {
            self.log.push("Awaiting peer...".to_string());
        }

        loop {
            if Instant::now().duration_since(self.last_draw) > Duration::from_millis(50) {
                self.draw()?;
                self.last_draw = Instant::now();
            }

            tokio::select! {
                Some(event) = event_rx.recv() => {
                    if let Err(e) = self.handle_event(event, &net_tx).await {
                        self.status = format!("ERROR: {:?}", e);
                        return Err(e);
                    }
                }
                res = tokio::task::spawn_blocking(|| event::poll(Duration::from_millis(10))) => {
                    if let Ok(Ok(true)) = res {
                        if let Event::Key(key) = event::read()? {
                            match key.code {
                                KeyCode::Enter => {
                                    if !self.input.is_empty() {
                                        let text = std::mem::take(&mut self.input);
                                        if self.session.state() == SessionState::Active {
                                            match self.session.send_message(&text) {
                                                Ok(frame) => {
                                                    let mut data = vec![Opcode::Relay as u8];
                                                    data.extend(frame.to_wire());
                                                    let _ = net_tx.send(data).await;
                                                    self.log.push(format!("You: {}", text));
                                                }
                                                Err(e) => self.log.push(format!("Error: {:?}", e)),
                                            }
                                        } else {
                                            self.log.push("Cannot send: Session not active".to_string());
                                        }
                                    }
                                }
                                KeyCode::Char(c) => self.input.push(c),
                                KeyCode::Backspace => { self.input.pop(); }
                                KeyCode::Esc => {
                                    let _ = net_tx.send(vec![Opcode::PeerQuit as u8]).await; // Explicit QUIT
                                    self.session.terminate();
                                    return Ok(());
                                }
                                _ => {}
                            }
                        }
                    }
                }
                _ = tokio::time::sleep(Duration::from_secs(1)) => {
                    if self.session.check_timeouts().is_err() {
                        self.status = "TERMINATED (Timeout)".to_string();
                        return Ok(());
                    }
                }
            }
        }
    }

    async fn handle_event(
        &mut self,
        event: AppEvent,
        net_tx: &mpsc::Sender<Vec<u8>>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        match event {
            AppEvent::Connected => {
                self.session.on_connected()?;
                self.status = "CONNECTED".to_string();
                if self.config.role == 'i' && self.session.state() == SessionState::Connected {
                    if let Ok(frame) = self.session.start_handshake() {
                        let mut data = vec![Opcode::Relay as u8];
                        data.extend(frame.to_wire());
                        net_tx.send(data).await?;
                    }
                }
            }
            AppEvent::Disconnected => {
                self.session.on_disconnected();
                self.status = "DISCONNECTED (Reconnecting...)".to_string();
            }
            AppEvent::SecurityViolation(msg) => {
                self.status = "SECURITY VIOLATION".to_string();
                self.log.push(msg);
                return Err("Security Violation - Certificate mismatch".into());
            }
            AppEvent::Notice(msg) => {
                self.log.push(msg);
            }
            AppEvent::MessageReceived(data) => {
                if data.is_empty() {
                    return Ok(());
                }
                let opcode = Opcode::try_from(data[0]).map_err(|_| "Unknown opcode")?;

                match opcode {
                    Opcode::Relay => {
                        // Relay (Peer -> Server -> Me)
                        if data.len() < 1 + LENGTH_PREFIX_SIZE {
                            return Ok(());
                        }
                        let body = &data[1..];
                        match Frame::parse(body) {
                            Ok(frame) => match self.session.on_receive(frame) {
                                Ok(res) => match res {
                                    SessionReceiveResult::Message(text) => {
                                        let clean_text = sanitize_text(&text);
                                        self.log.push(format!("Peer: {}", clean_text));
                                    }
                                    SessionReceiveResult::HandshakeResponse(f) => {
                                        let mut data = vec![Opcode::Relay as u8];
                                        data.extend(f.to_wire());
                                        net_tx.send(data).await?;
                                    }
                                    SessionReceiveResult::HandshakeCompleteWithResponse(f) => {
                                        self.log.push(
                                            "Handshake complete. Secure session active."
                                                .to_string(),
                                        );
                                        if let Some(fp) = self.session.fingerprint() {
                                            self.log.push(format!("Fingerprint: {}", fp));
                                        }
                                        let mut data = vec![Opcode::Relay as u8];
                                        data.extend(f.to_wire());
                                        net_tx.send(data).await?;
                                    }
                                    SessionReceiveResult::HandshakeComplete => {
                                        self.log.push(
                                            "Handshake complete. Secure session active."
                                                .to_string(),
                                        );
                                        if let Some(fp) = self.session.fingerprint() {
                                            self.log.push(format!("Fingerprint: {}", fp));
                                        }
                                    }
                                    SessionReceiveResult::Terminated => {
                                        self.log.push("Session terminated by peer.".to_string());
                                        self.session.terminate();
                                        return Err(Box::new(ProtocolError::SessionTerminated));
                                    }
                                    _ => {}
                                },
                                Err(e) => {
                                    self.log.push(format!("Protocol Error: {:?}", e));
                                    self.session.terminate();
                                    return Err(e.into());
                                }
                            },
                            Err(e) => {
                                self.log.push(format!("Framing Error: {:?}", e));
                                self.session.terminate();
                                return Err(e.into());
                            }
                        }
                    }
                    Opcode::PeerJoined => self.log.push("Peer joined.".to_string()),
                    Opcode::PeerQuit => {
                        self.log.push("Peer quit.".to_string());
                        self.session.terminate();
                        return Err(Box::new(ProtocolError::SessionTerminated));
                    }
                    Opcode::Expired => {
                        self.log.push("Session expired (TTL reached).".to_string());
                        self.session.terminate();
                        return Err(Box::new(ProtocolError::SessionTerminated));
                    }
                    Opcode::Error => {
                        // Error
                        let code = if data.len() > 1 { data[1] } else { 0 };
                        let msg = match code {
                            0x01 => "Role taken (session already has this peer)".to_string(),
                            0x02 => "Invalid format (framing error)".to_string(),
                            0x03 => "Unknown opcode".to_string(),
                            0x04 => "Unauthorized".to_string(),
                            0x05 => "Queue full (server backpressure)".to_string(),
                            0x06 => "Version mismatch (Server is v2.0)".to_string(),
                            _ => format!("Unknown server error (0x{:02x})", code),
                        };
                        self.log.push(format!("Server Error: {}", msg));
                    }
                    Opcode::VersionMismatch => {
                        self.log.push("CRITICAL: Protocol version mismatch! (Server is v2.0, client must match)".to_string());
                        self.session.terminate();
                        return Err(Box::new(ProtocolError::VersionMismatch));
                    }
                    Opcode::RateLimitExceeded => {
                        self.log.push("ERROR: Relay rate limit exceeded. Please wait before reconnecting.".to_string());
                        self.session.terminate();
                        return Err(Box::new(ProtocolError::RateLimitExceeded));
                    }
                    _ => {}
                }
            }
        }
        Ok(())
    }

    fn draw(&self) -> io::Result<()> {
        let mut stdout = io::stdout();
        execute!(stdout, cursor::MoveTo(0, 0))?;

        let id_disp = if self.config.session_id.len() > 8 {
            &self.config.session_id[..8]
        } else {
            &self.config.session_id
        };
        println!(
            "BlindWire | Session: {} | Role: {}",
            id_disp, self.config.role
        );
        println!(
            "Status: {:<30} | State: {:?}",
            self.status,
            self.session.state()
        );
        println!("{}", "=".repeat(60));

        if let Some(qr) = &self.qr_code {
            if self.session.state() != SessionState::Active {
                execute!(stdout, cursor::MoveTo(62, 3))?;
                print!("Scan to Join:");
                for (i, line) in qr.iter().enumerate() {
                    execute!(stdout, cursor::MoveTo(62, 4 + i as u16))?;
                    print!("{}", line);
                }
            }
        }

        for i in 0..10 {
            execute!(stdout, cursor::MoveTo(0, 3 + i as u16))?;
            execute!(stdout, Clear(ClearType::CurrentLine))?;
            if let Some(line) = self.log.get(self.log.len().saturating_sub(10) + i) {
                println!("{}", line);
            }
        }

        execute!(stdout, cursor::MoveTo(0, 14))?;
        println!("{}", "-".repeat(60));
        execute!(stdout, Clear(ClearType::CurrentLine))?;
        print!("> {}", self.input);
        stdout.flush()?;
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_uri_parsing() {
        let uri = "blindwire://relay.example.com:8080/ABCD123/i";
        let parsed = url::Url::parse(uri).unwrap();
        assert_eq!(parsed.scheme(), "blindwire");
        assert_eq!(parsed.host_str(), Some("relay.example.com"));
        assert_eq!(parsed.port(), Some(8080));
        
        let path_segments: Vec<&str> = parsed.path_segments().unwrap().collect();
        assert_eq!(path_segments[0], "ABCD123");
        assert_eq!(path_segments[1], "i");
    }

    #[test]
    fn test_qr_generation_logic() {
        let config = Config {
            server_url: "wss://relay.io:443".to_string(),
            session_id: "test-session".to_string(),
            role: 'i',
            insecure: false,
        };
        let session = Session::new_initiator().unwrap();
        let app = App {
            session,
            log: Vec::new(),
            input: String::new(),
            config,
            status: String::new(),
            last_draw: Instant::now(),
            qr_code: None,
        };
        
        let qr = app.generate_qr();
        assert!(qr.is_some());
        let qr_lines = qr.unwrap();
        assert!(!qr_lines.is_empty());
        // Verify it contains ASCII block characters
        assert!(qr_lines[0].contains('█') || qr_lines[0].contains('▀') || qr_lines[0].contains('▄') || qr_lines[0].contains(' '));
    }

    #[tokio::test]
    async fn test_pin_store_load_save() {
        let temp_dir = tempfile::tempdir().expect("tempdir failed");
        let pins_path = temp_dir.path().join("pins.json");
        
        // Mock path
        let mut store = PinStore::default();
        store.pins.insert("wss://test.com:443".to_string(), "hash1".to_string());
        
        let data = serde_json::to_string_pretty(&store).unwrap();
        fs::write(&pins_path, data).unwrap();
        
        // Load (manual load for testing)
        let data_read = fs::read_to_string(&pins_path).unwrap();
        let loaded: PinStore = serde_json::from_str(&data_read).unwrap();
        assert_eq!(loaded.pins.get("wss://test.com:443").unwrap(), "hash1");
    }

    #[tokio::test]
    async fn test_pinner_tofu_and_lock() {
        let (etx, _erx) = tokio::sync::mpsc::channel(32);
        let store = Arc::new(std::sync::Mutex::new(PinStore::default()));
        
        let pinner = Pinner {
            pin_key: "wss://test.com:443".to_string(),
            store: store.clone(),
            event_tx: etx,
        };

        let cert1 = CertificateDer::from(vec![1, 2, 3]);
        let cert2 = CertificateDer::from(vec![4, 5, 6]);

        // 1. First time - TOFU
        let res = pinner.verify_server_cert(
            &cert1,
            &[],
            &ServerName::try_from("test.com").unwrap(),
            &[],
            UnixTime::now(),
        );
        assert!(res.is_ok());
        
        {
            let s = store.lock().unwrap();
            assert_eq!(s.pins.get("wss://test.com:443").is_some(), true);
        }

        // 2. Second time - same cert - OK
        let res = pinner.verify_server_cert(
            &cert1,
            &[],
            &ServerName::try_from("test.com").unwrap(),
            &[],
            UnixTime::now(),
        );
        assert!(res.is_ok());

        // 3. Third time - different cert - FAIL
        let res = pinner.verify_server_cert(
            &cert2,
            &[],
            &ServerName::try_from("test.com").unwrap(),
            &[],
            UnixTime::now(),
        );
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn test_pinner_scoping() {
        let (etx, _erx) = tokio::sync::mpsc::channel(32);
        let store = Arc::new(std::sync::Mutex::new(PinStore::default()));
        
        let cert1 = CertificateDer::from(vec![1, 2, 3]);
        let cert2 = CertificateDer::from(vec![4, 5, 6]);

        // Key A
        let pinner_a = Pinner {
            pin_key: "wss://host1:443".to_string(),
            store: store.clone(),
            event_tx: etx.clone(),
        };
        // Key B (same host, different port)
        let pinner_b = Pinner {
            pin_key: "wss://host1:8443".to_string(),
            store: store.clone(),
            event_tx: etx.clone(),
        };

        // Pin Key A to Cert 1
        pinner_a.verify_server_cert(&cert1, &[], &ServerName::try_from("host1").unwrap(), &[], UnixTime::now()).unwrap();
        
        // Key B should still be empty and allow Cert 2 (TOFU)
        pinner_b.verify_server_cert(&cert2, &[], &ServerName::try_from("host1").unwrap(), &[], UnixTime::now()).unwrap();

        // Now both are locked
        assert!(pinner_a.verify_server_cert(&cert2, &[], &ServerName::try_from("host1").unwrap(), &[], UnixTime::now()).is_err());
        assert!(pinner_b.verify_server_cert(&cert1, &[], &ServerName::try_from("host1").unwrap(), &[], UnixTime::now()).is_err());
    }
}

fn sanitize_text(text: &str) -> String {
    text.chars()
        .filter(|c| {
            let val = *c as u32;
            
            // 1. Safe ASCII Whitelist:
            // - Printable ASCII: [0x20, 0x7E]
            // - Horizontal Tab: 0x09
            // - Line Feed: 0x0A
            if (val >= 0x20 && val <= 0x7E) || *c == '\n' || *c == '\t' {
                return true;
            }

            // 2. Block Dangerous Unicode (Visual Tricks & Control):
            // - C1 Control: [0x80, 0x9F]
            // - Bidi Control: [0x202A, 0x202E], [0x2066, 0x2069], 0x200E, 0x200F
            // - Joiners/Hide: [0x200B, 0x200D]
            if (val >= 0x80 && val <= 0x9F) ||
               (val >= 0x202A && val <= 0x202E) ||
               (val >= 0x2066 && val <= 0x2069) ||
               (val >= 0x200B && val <= 0x200D) ||
               *c == '\u{200E}' || *c == '\u{200F}' {
                return false;
            }

            // 3. Allow other non-control Unicode (multilingual support)
            // This allows the broad set of CJK, emoji, etc., while the above
            // explicit blocks target the most common terminal/UI bypass vectors.
            val > 0x9F
        })
        .collect()
}
