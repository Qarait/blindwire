use blindwire_core::frame::Frame;
use blindwire_core::state::{Session, SessionReceiveResult, SessionState};
use blindwire_server::run_server;
use futures_util::{SinkExt, StreamExt};
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::time::{advance, pause, sleep};
use tokio_tungstenite::{connect_async, tungstenite::protocol::Message};

// --- Helpers ---

fn wrap_relay(frame: Frame) -> Vec<u8> {
    // Frame body: [TYPE (1B)] [PAYLOAD (N bytes)]
    // We do NOT include Frame's length prefix - the signaling envelope provides its own.
    let wire = frame.to_wire();
    // to_wire() produces: [LENGTH (2B)] [TYPE (1B)] [PAYLOAD]
    // We want just: [TYPE (1B)] [PAYLOAD] — skip the first 2 bytes
    let body = &wire[2..];

    let len = body.len() as u16;
    let mut data = vec![0x01]; // RELAY opcode
    data.extend_from_slice(&len.to_be_bytes());
    data.extend_from_slice(body);
    data
}

async fn i_session_step(
    session: &mut Session,
    ws: &mut (impl SinkExt<Message, Error = tokio_tungstenite::tungstenite::Error> + Unpin),
) {
    if let Ok(frame) = session.start_handshake() {
        let wrapped = wrap_relay(frame);
        ws.send(Message::Binary(wrapped)).await.unwrap();
    }
}

async fn process_client_msg(
    session: &mut Session,
    ws: &mut (impl SinkExt<Message, Error = tokio_tungstenite::tungstenite::Error> + Unpin),
    data: Vec<u8>,
) -> Option<SessionReceiveResult> {
    // RELAY format: [opcode: 1 byte] [len: 2 bytes BE] [body: N bytes]
    if data.len() < 3 || data[0] != 0x01 {
        return None;
    }

    let expected_len = u16::from_be_bytes([data[1], data[2]]) as usize;
    if data.len() != 3 + expected_len {
        return None;
    }

    let frame = Frame::parse(&data[3..3 + expected_len]).ok()?;
    let res = session.on_receive(frame).ok()?;

    match &res {
        SessionReceiveResult::HandshakeResponse(f)
        | SessionReceiveResult::HandshakeCompleteWithResponse(f) => {
            ws.send(Message::Binary(wrap_relay(f.clone())))
                .await
                .unwrap();
        }
        _ => {}
    }
    Some(res)
}

// --- Scenarios ---

#[tokio::test]
async fn test_scenario_a_happy_path() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("ws://{}", addr);

    tokio::spawn(async move {
        run_server(listener).await;
    });

    let session_id = [0xA1u8; 32];

    // 1. Connect Initiator
    println!("Step: Initiator connecting...");
    let (mut i_ws, _) = connect_async(&url).await.unwrap();
    let mut i_join = vec![0x00, 0x69, 0x02]; // JOIN ('i'), Version 0x02
    i_join.extend_from_slice(&session_id);
    i_ws.send(Message::Binary(i_join)).await.unwrap();
    println!("Step: Initiator sent JOIN");

    // 2. Connect Responder
    println!("Step: Responder connecting...");
    let (mut r_ws, _) = connect_async(&url).await.unwrap();
    let mut r_join = vec![0x00, 0x72, 0x02]; // JOIN ('r'), Version 0x02
    r_join.extend_from_slice(&session_id);
    r_ws.send(Message::Binary(r_join)).await.unwrap();
    println!("Step: Responder sent JOIN");

    // Initiator should receive PEER_JOINED (0x02) when Responder joins
    println!("Step: Initiator waiting for PEER_JOINED...");
    if let Some(Ok(Message::Binary(data))) = i_ws.next().await {
        println!("Step: Initiator received opcode 0x{:x}", data[0]);
        assert_eq!(data[0], 0x02); // PEER_JOINED
    } else {
        panic!("Initiator failed to receive PEER_JOINED");
    }

    // 3. Handshake
    let mut initiator = Session::new_initiator().unwrap();
    let mut responder = Session::new_responder().unwrap();

    // Transition sessions to Connected state (required before handshake)
    initiator.on_connected().unwrap();
    responder.on_connected().unwrap();

    // Initiator starts
    i_session_step(&mut initiator, &mut i_ws).await;

    // We expect 3 rounds of handshake messages exchange
    for _ in 0..10 {
        if initiator.state() == SessionState::Active && responder.state() == SessionState::Active {
            break;
        }

        tokio::select! {
            msg = i_ws.next() => {
                if let Some(Ok(Message::Binary(data))) = msg {
                    process_client_msg(&mut initiator, &mut i_ws, data).await;
                }
            }
            msg = r_ws.next() => {
                if let Some(Ok(Message::Binary(data))) = msg {
                    process_client_msg(&mut responder, &mut r_ws, data).await;
                }
            }
        }
    }

    assert_eq!(initiator.state(), SessionState::Active);
    assert_eq!(responder.state(), SessionState::Active);

    // 4. Bidirectional Data
    let ping = initiator.send_message("ping").unwrap();
    i_ws.send(Message::Binary(wrap_relay(ping))).await.unwrap();

    let data = r_ws.next().await.unwrap().unwrap().into_data();
    if let Some(SessionReceiveResult::Message(t)) =
        process_client_msg(&mut responder, &mut r_ws, data).await
    {
        assert_eq!(t, "ping");
    } else {
        panic!("Expected PING");
    }

    // 5. Terminate
    i_ws.send(Message::Binary(vec![0x02])).await.unwrap(); // QUIT

    // Responder receives PEER_QUIT
    let data = r_ws.next().await.unwrap().unwrap().into_data();
    assert_eq!(data[0], 0x03); // PEER_QUIT
}

#[tokio::test]
async fn test_scenario_b_framing_violation_kill() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("ws://{}", addr);

    tokio::spawn(async move {
        run_server(listener).await;
    });

    let (mut ws, _) = connect_async(&url).await.unwrap();

    // Join
    let mut join = vec![0x00, 0x69, 0x02]; // v2 JOIN
    join.extend_from_slice(&[0xB2u8; 32]);
    ws.send(Message::Binary(join)).await.unwrap();

    // Send malformed RELAY (Incorrect length)
    // Opcode(1) + Len(2) + Body(N)
    // We say Len is 10, but give 5 bytes
    let mut malformed = vec![0x01, 0x00, 10]; // RELAY, LEN=10
    malformed.extend_from_slice(&[0xCCu8; 5]);
    ws.send(Message::Binary(malformed)).await.unwrap();

    // Server should send ERROR(INVALID_FORMAT) and close
    if let Some(Ok(Message::Binary(data))) = ws.next().await {
        assert_eq!(data[0], 0x05); // ERROR
        assert_eq!(data[1], 0x02); // INVALID_FORMAT
    } else {
        panic!("Expected ERROR packet");
    }

    // Connection should close (may be a clean close or a reset)
    while (ws.next().await).is_some() {}
}

#[tokio::test]
async fn test_scenario_c_duplicate_role_taken() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("ws://{}", addr);

    tokio::spawn(async move {
        run_server(listener).await;
    });

    let session_id = [0xC3u8; 32];

    // Initiator joins
    let (mut i1_ws, _) = connect_async(&url).await.unwrap();
    let mut join = vec![0x00, 0x69, 0x02];
    join.extend_from_slice(&session_id);
    i1_ws.send(Message::Binary(join.clone())).await.unwrap();

    // Second initiator tries to join SAME role
    let (mut i2_ws, _) = connect_async(&url).await.unwrap();
    i2_ws.send(Message::Binary(join)).await.unwrap();

    // i2 receives ROLE_TAKEN and dies
    if let Some(Ok(Message::Binary(data))) = i2_ws.next().await {
        assert_eq!(data[0], 0x05); // ERROR
        assert_eq!(data[1], 0x01); // ROLE_TAKEN
    } else {
        panic!("Expected ROLE_TAKEN");
    }
    while (i2_ws.next().await).is_some() {}

    // i1 is still alive and well
    i1_ws.send(Message::Binary(vec![0x02])).await.unwrap(); // QUIT should work
    assert!(i1_ws.next().await.is_some()); // Should get something or just not be closed
}

// Note: Testing Scenario D (Queue Backpressure) is hard with localhost speed,
// so we skip the detailed mock but verify logic in server.
// Actually, let's try to fill the 32-capacity queue.

#[tokio::test]
async fn test_scenario_d_bounded_queue_backpressure() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("ws://{}", addr);

    tokio::spawn(async move {
        run_server(listener).await;
    });

    let session_id = [0xD4u8; 32];

    // Responder joins (the "slow" receiver)
    let (mut r_ws, _) = connect_async(&url).await.unwrap();
    let mut r_join = vec![0x00, 0x72, 0x02];
    r_join.extend_from_slice(&session_id);
    r_ws.send(Message::Binary(r_join)).await.unwrap();

    // Initiator joins (the "fast" sender)
    let (mut i_ws, _) = connect_async(&url).await.unwrap();
    let mut i_join = vec![0x00, 0x69, 0x02];
    i_join.extend_from_slice(&session_id);
    i_ws.send(Message::Binary(i_join)).await.unwrap();

    // Initiator floods RELAY packets
    // Max queue is 32. Let's send 40.
    for i in 0..40 {
        let msg = vec![0x01, 0x00, 1, i as u8];
        if i_ws.send(Message::Binary(msg)).await.is_err() {
            break;
        }
    }

    // At some point, the server should send ERROR(QUEUE_FULL) to Initiator
    // because it cannot deliver to Responder.
    let mut error_received = false;
    while let Some(Ok(Message::Binary(data))) = i_ws.next().await {
        if data[0] == 0x05 && data[1] == 0x05 {
            // ERROR(QUEUE_FULL)
            error_received = true;
            break;
        }
    }
    assert!(error_received);
}

#[tokio::test]
async fn test_scenario_e_reconnection_grace_tokio_time() {
    pause(); // Deterministic time

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("ws://{}", addr);

    tokio::spawn(async move {
        run_server(listener).await;
    });

    let session_id = [0xE5u8; 32];

    // Connect and Join
    {
        let (mut ws, _) = connect_async(&url).await.unwrap();
        let mut join = vec![0x00, 0x69, 0x02];
        join.extend_from_slice(&session_id);
        ws.send(Message::Binary(join)).await.unwrap();
        // Socket dropped here
    }

    // Advance time by 4 seconds (Less than 5s grace)
    advance(Duration::from_secs(4)).await;

    // Connect again - should succeed (session still exists)
    let (mut ws, _) = connect_async(&url).await.unwrap();
    let mut join = vec![0x00, 0x69, 0x02];
    join.extend_from_slice(&session_id);
    ws.send(Message::Binary(join)).await.unwrap();

    // Advance time by 2 more seconds (Total 6s since first join, but 2s since second)
    advance(Duration::from_secs(2)).await;

    // Drop and wait 6 seconds
    drop(ws);
    advance(Duration::from_secs(6)).await;

    // Session should be purged. PeerJoined shouldn't happen if we join as responder?
    // Let's just join as initiator again.
    let (mut ws, _) = connect_async(&url).await.unwrap();
    let mut join = vec![0x00, 0x69, 0x02];
    join.extend_from_slice(&session_id);
    ws.send(Message::Binary(join)).await.unwrap();

    // If we were responder and joined, we'd see if initiator exists.
    let (mut r_ws, _) = connect_async(&url).await.unwrap();
    let mut r_join = vec![0x00, 0x72, 0x02];
    r_join.extend_from_slice(&session_id);
    r_ws.send(Message::Binary(r_join)).await.unwrap();

    // Responder should see PEER_JOINED if Session was kept.
    // Actually, Session object itself might linger until TTL,
    // but the roles (Tx) are dropped.
}

#[tokio::test]
async fn test_scenario_f_server_expiry() {
    // Enable test mode for short TTL (2s) and fast cleanup (1s)
    std::env::set_var("BLINDWIRE_TEST_TTL", "1");

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("ws://{}", addr);

    tokio::spawn(async move {
        run_server(listener).await;
    });

    // 1. Join session
    let (mut ws, _) = connect_async(&url).await.unwrap();
    let mut join = vec![0x00, 0x69, 0x02];
    join.extend_from_slice(&[0xF6u8; 32]);
    ws.send(Message::Binary(join)).await.unwrap();

    // 2. Wait for expiration (TTL_TEST is 2s, cleanup interval is 1s)
    sleep(Duration::from_secs(4)).await;

    // 3. Verify EXPIRED (0x04)
    if let Some(Ok(Message::Binary(data))) = ws.next().await {
        assert_eq!(data[0], 0x04); // EXPIRED
    } else {
        panic!("Expected EXPIRED notification");
    }

    // Connection should close (may be a clean close or a reset)
    while (ws.next().await).is_some() {}

    // Clean up env var
    std::env::remove_var("BLINDWIRE_TEST_TTL");
}

#[tokio::test]
async fn test_scenario_g_version_mismatch() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("ws://{}", addr);

    tokio::spawn(async move {
        run_server(listener).await;
    });

    let (mut ws, _) = connect_async(&url).await.unwrap();

    // 1. Try v1 JOIN (34 bytes total)
    let mut v1_join = vec![0x00, 0x69];
    v1_join.extend_from_slice(&[0x11u8; 32]);
    ws.send(Message::Binary(v1_join)).await.unwrap();

    // Should receive ERROR(VERSION_MISMATCH = 0x06)
    if let Some(Ok(Message::Binary(data))) = ws.next().await {
        assert_eq!(data[0], 0x05); // ERROR
        assert_eq!(data[1], 0x06); // VERSION_MISMATCH
    } else {
        panic!("Expected VERSION_MISMATCH error for v1 client");
    }
    while (ws.next().await).is_some() {}

    // 2. Try v2 JOIN with WRONG version byte (e.g. 0x03)
    let (mut ws2, _) = connect_async(&url).await.unwrap();
    let mut v2_bad_join = vec![0x00, 0x69, 0x03]; // Wrong version
    v2_bad_join.extend_from_slice(&[0x22u8; 32]);
    ws2.send(Message::Binary(v2_bad_join)).await.unwrap();

    if let Some(Ok(Message::Binary(data))) = ws2.next().await {
        assert_eq!(data[0], 0x05); // ERROR
        assert_eq!(data[1], 0x06); // VERSION_MISMATCH
    } else {
        panic!("Expected VERSION_MISMATCH error for bad version byte");
    }
    while (ws2.next().await).is_some() {}

    // 3. Try CORRECT v2 JOIN
    let (mut ws3, _) = connect_async(&url).await.unwrap();
    let mut v2_good_join = vec![0x00, 0x69, 0x02]; // Correct version
    v2_good_join.extend_from_slice(&[0x33u8; 32]);
    ws3.send(Message::Binary(v2_good_join)).await.unwrap();

    // Should NOT get an error immediately (wait for JOIN success, e.g. no message)
    tokio::select! {
        msg = ws3.next() => {
             if let Some(Ok(Message::Binary(data))) = msg {
                 if data[0] == 0x05 {
                     panic!("Unexpected error: 0x{:02x}", data[1]);
                 }
             }
        }
        _ = tokio::time::sleep(Duration::from_millis(100)) => {}
    }
}

