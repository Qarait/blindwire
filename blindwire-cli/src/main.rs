use std::io::{self, Write};
use std::time::{Duration, Instant};
use futures_util::{StreamExt, SinkExt};
use tokio::sync::mpsc;
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::protocol::Message;
use crossterm::{
    event::{self, Event, KeyCode},
    terminal::{enable_raw_mode, disable_raw_mode, Clear, ClearType},
    execute, cursor,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::RngCore;

use blindwire_core::state::{Session, SessionState, SessionReceiveResult};
use blindwire_core::frame::{Frame, LENGTH_PREFIX_SIZE};

const DEFAULT_SERVER: &str = "wss://127.0.0.1:8080";
const RECONNECT_DELAY: Duration = Duration::from_secs(1);

#[derive(Debug)]
struct Config {
    server_url: String,
    session_id: String,
    role: char,
    insecure: bool,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
enum Opcode {
    Join = 0x00,
    Relay = 0x01,
    PeerJoined = 0x02,
    PeerQuit = 0x03,
    Expired = 0x04,
    Error = 0x05,
}

enum AppEvent {
    Connected,
    Disconnected,
    MessageReceived(Vec<u8>),
}

struct App {
    session: Session,
    log: Vec<String>,
    input: String,
    config: Config,
    status: String,
    last_draw: Instant,
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
                server_url = args[i+1].clone();
                i += 1;
            }
            "--session" if i + 1 < args.len() => {
                session_id = args[i+1].clone();
                role = 'r'; // Providing a session implies joining as responder
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
    if server_url.starts_with("ws://") && !insecure {
        eprintln!("ERROR: ws:// is only allowed with --insecure-dev on localhost.");
        return Ok(());
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
    };

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
    async fn run(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let (event_tx, mut event_rx) = mpsc::channel::<AppEvent>(32);
        let (net_tx, mut net_rx) = mpsc::channel::<Vec<u8>>(32);
        
        let server_url = self.config.server_url.clone();
        let session_id = self.config.session_id.clone();
        let role = self.config.role;

        // Networking thread
        tokio::spawn(async move {
            loop {
                if let Ok((ws_stream, _)) = connect_async(&server_url).await {
                    let (mut ws_tx, mut ws_rx) = ws_stream.split();
                    
                    // Send JOIN
                    let role_byte = if role == 'i' { 0x69u8 } else { 0x72u8 };
                    let mut join_packet = vec![Opcode::Join as u8, role_byte];
                    let decoded_id = URL_SAFE_NO_PAD.decode(&session_id).unwrap_or_else(|_| vec![0u8; 16]);
                    // Pad to 32 bytes if needed (v1.1 spec says 32B ID)
                    let mut id_32 = [0u8; 32];
                    if decoded_id.len() >= 32 {
                        id_32.copy_from_slice(&decoded_id[..32]);
                    } else {
                        id_32[..decoded_id.len()].copy_from_slice(&decoded_id);
                    }
                    join_packet.extend_from_slice(&id_32);
                    
                    if ws_tx.send(Message::Binary(join_packet)).await.is_ok() {
                        let _ = event_tx.send(AppEvent::Connected).await;

                        loop {
                            tokio::select! {
                                Some(data) = net_rx.recv() => {
                                    if ws_tx.send(Message::Binary(data)).await.is_err() { break; }
                                }
                                msg = ws_rx.next() => {
                                    match msg {
                                        Some(Ok(Message::Binary(data))) => {
                                            let _ = event_tx.send(AppEvent::MessageReceived(data)).await;
                                        }
                                        _ => break,
                                    }
                                }
                            }
                        }
                    }
                    let _ = event_tx.send(AppEvent::Disconnected).await;
                }
                tokio::time::sleep(RECONNECT_DELAY).await;
            }
        });

        self.log.push(format!("Server: {}", self.config.server_url));
        self.log.push(format!("Session: {}", self.config.session_id));
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
                    self.handle_event(event, &net_tx).await?;
                }
                Ok(true) = tokio::task::spawn_blocking(|| event::poll(Duration::from_millis(10))) => {
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
                                let _ = net_tx.send(vec![0x02]).await; // TERMINATE
                                return Ok(());
                            }
                            _ => {}
                        }
                    }
                }
                _ = tokio::time::sleep(Duration::from_secs(1)) => {
                    if let Err(_) = self.session.check_timeouts() {
                        self.status = "TERMINATED (Timeout)".to_string();
                        return Ok(());
                    }
                }
            }
        }
    }

    async fn handle_event(&mut self, event: AppEvent, net_tx: &mpsc::Sender<Vec<u8>>) -> Result<(), Box<dyn std::error::Error>> {
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
            AppEvent::MessageReceived(data) => {
                if data.is_empty() { return Ok(()); }
                let opcode = data[0];
                
                match opcode {
                    0x01 => { // Relay (Peer -> Server -> Me)
                        if data.len() < 1 + LENGTH_PREFIX_SIZE { return Ok(()); }
                        let body = &data[1..];
                        match Frame::parse(body) {
                            Ok(frame) => {
                                match self.session.on_receive(frame) {
                                    Ok(res) => match res {
                                        SessionReceiveResult::Message(text) => {
                                            self.log.push(format!("Peer: {}", text));
                                        }
                                        SessionReceiveResult::HandshakeResponse(f) => {
                                            let mut data = vec![Opcode::Relay as u8];
                                            data.extend(f.to_wire());
                                            net_tx.send(data).await?;
                                        }
                                        SessionReceiveResult::HandshakeCompleteWithResponse(f) => {
                                            self.log.push("Handshake complete. Secure session active.".to_string());
                                            if let Some(fp) = self.session.fingerprint() {
                                                self.log.push(format!("Fingerprint: {}", fp));
                                            }
                                            let mut data = vec![Opcode::Relay as u8];
                                            data.extend(f.to_wire());
                                            net_tx.send(data).await?;
                                        }
                                        SessionReceiveResult::HandshakeComplete => {
                                            self.log.push("Handshake complete. Secure session active.".to_string());
                                            if let Some(fp) = self.session.fingerprint() {
                                                self.log.push(format!("Fingerprint: {}", fp));
                                            }
                                        }
                                        SessionReceiveResult::Terminated => {
                                            self.log.push("Session terminated by peer.".to_string());
                                            return Ok(());
                                        }
                                        _ => {}
                                    },
                                    Err(e) => {
                                        self.log.push(format!("Protocol Error: {:?}", e));
                                        return Ok(());
                                    }
                                }
                            }
                            Err(e) => self.log.push(format!("Framing Error: {:?}", e)),
                        }
                    }
                    0x02 => self.log.push("Peer joined.".to_string()),
                    0x03 => {
                        self.log.push("Peer quit.".to_string());
                        self.session.on_disconnected();
                    }
                    0x05 => { // Error
                        let code = if data.len() > 1 { data[1] } else { 0 };
                        let msg = match code {
                            0x01 => "Role taken (session already has this peer)".to_string(),
                            0x02 => "Invalid format (framing error)".to_string(),
                            0x03 => "Unknown opcode".to_string(),
                            0x04 => "Unauthorized".to_string(),
                            0x05 => "Queue full (server backpressure)".to_string(),
                            _ => format!("Unknown server error (0x{:02x})", code),
                        };
                        self.log.push(format!("Server Error: {}", msg));
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
        
        let id_disp = if self.config.session_id.len() > 8 { &self.config.session_id[..8] } else { &self.config.session_id };
        println!("BlindWire | Session: {} | Role: {}", id_disp, self.config.role);
        println!("Status: {:<30} | State: {:?}", self.status, self.session.state());
        println!("{}", "=".repeat(60));
        
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
