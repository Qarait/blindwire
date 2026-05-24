//! Headless Reality Smoke Responder
//!
//! Acts as "instance B" in the two-instance E2E smoke test.
//! Uses the same high-level `SecureSession` API as the Tauri desktop app,
//! so it validates the same end-to-end transport path.
//!
//! # Usage
//!
//!   smoke-responder <invite_uri> [--timeout-secs <N>] [--expect-msg <text>]
//!
//! # Exit codes
//!
//!   0  All smoke assertions passed
//!   1  Handshake failed or assertion failed
//!   2  Timeout (transport hung)
//!
//! # What it does
//!
//!   1. Parses the blindwire:// invite URI
//!   2. Derives session_id = SHA-256(room) (same as the Tauri app)
//!   3. Connects as Responder via SecureSession::connect()
//!   4. Prints the real 7-emoji SAS to stdout → operator checks it matches instance A
//!   5. Waits for one inbound message from instance A
//!   6. Echoes "<echo>: <original>" back to instance A
//!   7. Exits 0 on success

use sha2::{Digest, Sha256};
use std::process;
use std::time::Duration;
use blindwire_core::sas;
use blindwire_core::invite::InvitePayload;
use blindwire_transport::{SecureSession, TransportConfig};

const DEFAULT_TIMEOUT_SECS: u64 = 30;

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: smoke-responder <invite_uri> [--timeout-secs <N>] [--expect-msg <text>]");
        process::exit(2);
    }

    let invite_uri = &args[1];
    let mut timeout_secs = DEFAULT_TIMEOUT_SECS;
    let mut expect_msg: Option<String> = None;

    let mut i = 2;
    while i < args.len() {
        match args[i].as_str() {
            "--timeout-secs" if i + 1 < args.len() => {
                timeout_secs = args[i + 1].parse().unwrap_or(DEFAULT_TIMEOUT_SECS);
                i += 2;
            }
            "--expect-msg" if i + 1 < args.len() => {
                expect_msg = Some(args[i + 1].clone());
                i += 2;
            }
            _ => { i += 1; }
        }
    }

    let result = tokio::time::timeout(
        Duration::from_secs(timeout_secs),
        run_smoke(invite_uri, expect_msg),
    ).await;

    match result {
        Ok(Ok(())) => {
            println!("[SMOKE] PASS");
            process::exit(0);
        }
        Ok(Err(e)) => {
            eprintln!("[SMOKE] FAIL: {}", e);
            process::exit(1);
        }
        Err(_elapsed) => {
            eprintln!("[SMOKE] TIMEOUT after {}s", timeout_secs);
            process::exit(2);
        }
    }
}

async fn run_smoke(invite_uri: &str, expect_msg: Option<String>) -> Result<(), String> {
    // ── 1. Parse the invite URI ──────────────────────────────────────────────
    let invite = InvitePayload::parse(invite_uri)
        .map_err(|e| format!("invite parse failed: {:?}", e))?;

    println!("[SMOKE] Invite parsed");
    println!("[SMOKE]   room     : {}", invite.room);
    println!("[SMOKE]   relay    : {}", invite.relay_url);
    println!("[SMOKE]   expires  : {}", invite.exp);

    // ── 2. Derive session_id — must match Tauri's session_id_from_room() ─────
    let session_id: [u8; 32] = {
        let hash = Sha256::digest(invite.room.as_bytes());
        let mut id = [0u8; 32];
        id.copy_from_slice(&hash);
        id
    };

    // ── 3. Build TransportConfig ─────────────────────────────────────────────
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    let mut token_bytes = [0u8; 32];
    let decoded = URL_SAFE_NO_PAD.decode(&invite.token)
        .map_err(|e| format!("invalid token encoding: {}", e))?;
    if decoded.len() != 32 {
        return Err("token must be exactly 32 bytes".to_string());
    }
    token_bytes.copy_from_slice(&decoded);

    let relay_url = invite.relay_url.to_string();
    let is_insecure = relay_url.starts_with("ws://");
    let mut config = TransportConfig::responder(relay_url, session_id, token_bytes);
    if is_insecure {
        config = config.with_insecure_dev();
    }

    // ── 4. Connect and complete Noise handshake ───────────────────────────────
    println!("[SMOKE] Connecting as Responder...");
    let (mut session, _) = SecureSession::connect(config).await
        .map_err(|e| format!("connect failed: {:?}", e))?;

    session.handshake().await
        .map_err(|e| format!("handshake failed: {:?}", e))?;

    println!("[SMOKE] Handshake complete ✓");

    // ── 5. Print the real 7-emoji SAS ────────────────────────────────────────
    let fingerprint_hex = session.fingerprint().unwrap_or_default();
    let mut shared_secret = [0u8; 32];
    if let Ok(bytes) = hex::decode(&fingerprint_hex) {
        let len = bytes.len().min(32);
        shared_secret[..len].copy_from_slice(&bytes[..len]);
    }
    let emojis = sas::generate(&shared_secret, &session_id);
    println!("[SMOKE] SAS (verify this matches instance A): {}", emojis.join(" "));
    println!("[SMOKE] Fingerprint: {}", fingerprint_hex);

    // ── 6. Wait for one inbound message from instance A ──────────────────────
    println!("[SMOKE] Waiting for message from instance A...");
    let received = session.recv().await
        .map_err(|e| format!("recv failed: {:?}", e))?;

    let received_text = String::from_utf8_lossy(received.as_bytes()).to_string();
    println!("[SMOKE] Received: '{}'", received_text);

    // Optional: assert the message matches what we expected
    if let Some(ref expected) = expect_msg {
        if &received_text != expected {
            return Err(format!(
                "message mismatch: expected '{}', got '{}'",
                expected, received_text
            ));
        }
        println!("[SMOKE] Message content ✓");
    }

    // ── 7. Echo back ──────────────────────────────────────────────────────────
    let echo = format!("echo: {}", received_text);
    session.send_text(&echo).await
        .map_err(|e| format!("send failed: {:?}", e))?;

    println!("[SMOKE] Echo sent: '{}'", echo);

    // ── 8. Clean disconnect ───────────────────────────────────────────────────
    session.burn();
    println!("[SMOKE] Session burned cleanly ✓");

    Ok(())
}
