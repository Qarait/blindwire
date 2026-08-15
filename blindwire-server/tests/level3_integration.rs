#![allow(clippy::uninlined_format_args)]

use blindwire_core::frame::Frame;
use blindwire_core::state::{Session, SessionReceiveResult, SessionState};
use blindwire_server::run_server;
use futures_util::{SinkExt, StreamExt};
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::time::{advance, pause, sleep};
use tokio_tungstenite::{
    connect_async, tungstenite::protocol::Message, MaybeTlsStream, WebSocketStream,
};

// --- Helpers ---

fn wrap_relay(frame: Frame) -> Vec<u8> {
    let wire = frame.to_wire();
    let len = wire.len() as u16;
    let mut data = vec![0x01]; // RELAY opcode
    data.extend_from_slice(&len.to_be_bytes());
    data.extend_from_slice(&wire);
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
    if data.len() < 3 || data[0] != 0x01 {
        return None;
    }
    let expected_len = u16::from_be_bytes([data[1], data[2]]) as usize;
    if data.len() != 3 + expected_len {
        return None;
    }
    if expected_len < 3 {
        return None;
    }
    let frame_len = Frame::read_length(&[data[3], data[4]]).ok()?;
    if expected_len != frame_len + 2 {
        return None;
    }
    let frame = Frame::parse(&data[5..3 + expected_len]).ok()?;
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

type TestWebSocket = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

async fn start_test_server() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        run_server(listener).await;
    });
    format!("ws://{addr}")
}

async fn next_binary(ws: &mut TestWebSocket) -> Vec<u8> {
    match tokio::time::timeout(Duration::from_secs(1), ws.next())
        .await
        .expect("timed out waiting for server packet")
    {
        Some(Ok(Message::Binary(data))) => data,
        other => panic!("expected binary server packet, got {other:?}"),
    }
}

async fn assert_no_binary(ws: &mut TestWebSocket) {
    assert!(
        tokio::time::timeout(Duration::from_millis(100), ws.next())
            .await
            .is_err(),
        "server unexpectedly sent or closed the connection"
    );
}

async fn connect_initiator(
    url: &str,
    session_id: [u8; 32],
    version: u8,
) -> (TestWebSocket, [u8; 32]) {
    let (mut ws, _) = connect_async(url).await.unwrap();
    let mut join = vec![0x00, 0x69, version];
    join.extend_from_slice(&session_id);
    ws.send(Message::Binary(join)).await.unwrap();

    let packet = next_binary(&mut ws).await;
    assert_eq!(packet.len(), 33, "expected TOKEN packet, got {packet:?}");
    assert_eq!(packet[0], 0x06);
    let mut token = [0u8; 32];
    token.copy_from_slice(&packet[1..]);
    (ws, token)
}

async fn connect_responder(
    url: &str,
    session_id: [u8; 32],
    token: [u8; 32],
    version: u8,
) -> TestWebSocket {
    let (mut ws, _) = connect_async(url).await.unwrap();
    let mut join = vec![0x00, 0x72, version];
    join.extend_from_slice(&session_id);
    join.extend_from_slice(&token);
    ws.send(Message::Binary(join)).await.unwrap();
    ws
}

async fn connect_pair(url: &str, session_id: [u8; 32]) -> (TestWebSocket, TestWebSocket, [u8; 32]) {
    let (mut initiator, token) = connect_initiator(url, session_id, 0x03).await;
    let mut responder = connect_responder(url, session_id, token, 0x03).await;
    assert_eq!(next_binary(&mut initiator).await, vec![0x02]);
    assert_eq!(next_binary(&mut responder).await, vec![0x02]);
    (initiator, responder, token)
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

    println!("Step: Initiator connecting...");
    let (mut i_ws, _) = connect_async(&url).await.unwrap();
    let mut i_join = vec![0x00, 0x69, 0x03]; // JOIN ('i'), signaling v3
    i_join.extend_from_slice(&session_id);
    i_ws.send(Message::Binary(i_join)).await.unwrap();
    println!("Step: Initiator sent JOIN");

    // Initiator must receive TOKEN_MINTED (0x06) first
    let mut token = [0u8; 32];
    if let Some(Ok(Message::Binary(data))) = i_ws.next().await {
        assert_eq!(data[0], 0x06); // Token minted
        token.copy_from_slice(&data[1..33]);
    } else {
        panic!("Failed to receive TOKEN_MINTED");
    }

    println!("Step: Responder connecting...");
    let (mut r_ws, _) = connect_async(&url).await.unwrap();
    let mut r_join = vec![0x00, 0x72, 0x03]; // JOIN ('r'), signaling v3
    r_join.extend_from_slice(&session_id);
    r_join.extend_from_slice(&token); // Responder MUST provide token
    r_ws.send(Message::Binary(r_join)).await.unwrap();
    println!("Step: Responder sent JOIN");

    println!("Step: Initiator waiting for PEER_JOINED...");
    if let Some(Ok(Message::Binary(data))) = i_ws.next().await {
        assert_eq!(data[0], 0x02); // PEER_JOINED
    } else {
        panic!("Initiator failed to receive PEER_JOINED");
    }

    let mut initiator = Session::new_initiator().unwrap();
    let mut responder = Session::new_responder().unwrap();
    initiator.on_connected().unwrap();
    responder.on_connected().unwrap();

    i_session_step(&mut initiator, &mut i_ws).await;

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

    i_ws.send(Message::Binary(vec![0x03])).await.unwrap();
    r_ws.send(Message::Binary(vec![0x03])).await.unwrap();
    assert_eq!(next_binary(&mut i_ws).await, vec![0x07]);
    assert_eq!(next_binary(&mut r_ws).await, vec![0x07]);

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

    i_ws.send(Message::Binary(vec![0x02])).await.unwrap(); // QUIT

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

    // Use Initiator to avoid needing the token logic for JOIN
    let mut join = vec![0x00, 0x69, 0x03]; // signaling v3 JOIN
    join.extend_from_slice(&[0xB2u8; 32]);
    ws.send(Message::Binary(join)).await.unwrap();

    // Consume the TOKEN_MINTED response
    ws.next().await.unwrap().unwrap();

    // Send malformed RELAY (Incorrect length)
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

    let (mut i1_ws, _) = connect_async(&url).await.unwrap();
    let mut join = vec![0x00, 0x69, 0x03];
    join.extend_from_slice(&session_id);
    i1_ws.send(Message::Binary(join.clone())).await.unwrap();

    // Save the legitimate initiator's token.
    let original_token = match i1_ws.next().await.unwrap().unwrap() {
        Message::Binary(data) if data.len() == 33 && data[0] == 0x06 => {
            let mut token = [0u8; 32];
            token.copy_from_slice(&data[1..]);
            token
        }
        other => panic!("Expected TOKEN_MINTED, got {other:?}"),
    };

    let (mut i2_ws, _) = connect_async(&url).await.unwrap();
    i2_ws.send(Message::Binary(join)).await.unwrap();

    // A duplicate initiator must be rejected before any replacement token is minted.
    if let Some(Ok(Message::Binary(data))) = i2_ws.next().await {
        assert_eq!(data[0], 0x05); // ERROR
        assert_eq!(data[1], 0x01); // ROLE_TAKEN
    } else {
        panic!("Expected ROLE_TAKEN");
    }
    while (i2_ws.next().await).is_some() {}

    // The rejected duplicate must not invalidate the original invitation.
    let (mut r_ws, _) = connect_async(&url).await.unwrap();
    let mut responder_join = vec![0x00, 0x72, 0x03];
    responder_join.extend_from_slice(&session_id);
    responder_join.extend_from_slice(&original_token);
    r_ws.send(Message::Binary(responder_join)).await.unwrap();

    let peer_joined = i1_ws.next().await.unwrap().unwrap().into_data();
    assert_eq!(peer_joined[0], 0x02);

    r_ws.send(Message::Binary(vec![0x02])).await.unwrap();
    i1_ws.send(Message::Binary(vec![0x02])).await.unwrap();
    assert!(i1_ws.next().await.is_some());
}

#[tokio::test]
async fn test_responder_token_reusable_before_handshake_starts() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("ws://{addr}");

    tokio::spawn(async move {
        run_server(listener).await;
    });

    let session_id = [0xC4u8; 32];
    let (mut i_ws, _) = connect_async(&url).await.unwrap();
    let mut i_join = vec![0x00, 0x69, 0x03];
    i_join.extend_from_slice(&session_id);
    i_ws.send(Message::Binary(i_join)).await.unwrap();

    let token_packet = i_ws.next().await.unwrap().unwrap().into_data();
    let mut token = [0u8; 32];
    token.copy_from_slice(&token_packet[1..33]);

    let mut responder_join = vec![0x00, 0x72, 0x03];
    responder_join.extend_from_slice(&session_id);
    responder_join.extend_from_slice(&token);

    let (mut r1_ws, _) = connect_async(&url).await.unwrap();
    r1_ws
        .send(Message::Binary(responder_join.clone()))
        .await
        .unwrap();
    assert_eq!(i_ws.next().await.unwrap().unwrap().into_data()[0], 0x02);

    drop(r1_ws);
    assert_eq!(i_ws.next().await.unwrap().unwrap().into_data()[0], 0x03);

    let (mut r2_ws, _) = connect_async(&url).await.unwrap();
    r2_ws.send(Message::Binary(responder_join)).await.unwrap();

    assert_eq!(i_ws.next().await.unwrap().unwrap().into_data()[0], 0x02);
}

#[tokio::test]
async fn relay_traffic_never_substitutes_for_explicit_completion() {
    let url = start_test_server().await;
    let session_id = [0xC5u8; 32];
    let (mut initiator, mut responder, token) = connect_pair(&url, session_id).await;

    let first = wrap_relay(Frame::handshake(vec![0x11]).unwrap());
    initiator
        .send(Message::Binary(first.clone()))
        .await
        .unwrap();
    assert_eq!(next_binary(&mut responder).await, first);

    let second = wrap_relay(Frame::handshake(vec![0x22]).unwrap());
    responder
        .send(Message::Binary(second.clone()))
        .await
        .unwrap();
    assert_eq!(next_binary(&mut initiator).await, second);

    drop(responder);
    assert_eq!(next_binary(&mut initiator).await, vec![0x03]);

    let mut replacement = connect_responder(&url, session_id, token, 0x03).await;
    assert_eq!(next_binary(&mut initiator).await, vec![0x02]);
    assert_eq!(next_binary(&mut replacement).await, vec![0x02]);

    initiator.send(Message::Binary(vec![0x03])).await.unwrap();
    replacement.send(Message::Binary(vec![0x03])).await.unwrap();
    assert_eq!(next_binary(&mut initiator).await, vec![0x07]);
    assert_eq!(next_binary(&mut replacement).await, vec![0x07]);

    let mut replay = connect_responder(&url, session_id, token, 0x03).await;
    assert_eq!(next_binary(&mut replay).await, vec![0x05, 0x04]);
}

#[tokio::test]
async fn test_scenario_d_bounded_queue_backpressure() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("ws://{}", addr);

    tokio::spawn(async move {
        run_server(listener).await;
    });

    let session_id = [0xD4u8; 32];

    let (mut i_ws, _) = connect_async(&url).await.unwrap();
    let mut i_join = vec![0x00, 0x69, 0x03];
    i_join.extend_from_slice(&session_id);
    i_ws.send(Message::Binary(i_join)).await.unwrap();

    let mut token = [0u8; 32];
    if let Some(Ok(Message::Binary(data))) = i_ws.next().await {
        token.copy_from_slice(&data[1..33]);
    } else {
        panic!("Failed to get token");
    }

    let (mut r_ws, _) = connect_async(&url).await.unwrap();
    let mut r_join = vec![0x00, 0x72, 0x03];
    r_join.extend_from_slice(&session_id);
    r_join.extend_from_slice(&token);
    r_ws.send(Message::Binary(r_join)).await.unwrap();

    // Initiator gets PEER_JOINED
    i_ws.next().await.unwrap().unwrap();

    for i in 0..40 {
        let msg = vec![0x01, 0x00, 1, i as u8];
        if i_ws.send(Message::Binary(msg)).await.is_err() {
            break;
        }
    }

    let mut error_received = false;
    while let Some(Ok(Message::Binary(data))) = i_ws.next().await {
        if data[0] == 0x05 && data[1] == 0x05 {
            error_received = true;
            break;
        }
    }
    assert!(error_received);
}

#[tokio::test]
async fn test_scenario_e_reconnection_grace_tokio_time() {
    pause();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("ws://{}", addr);

    tokio::spawn(async move {
        run_server(listener).await;
    });

    let session_id = [0xE5u8; 32];

    {
        let (mut ws, _) = connect_async(&url).await.unwrap();
        let mut join = vec![0x00, 0x69, 0x03];
        join.extend_from_slice(&session_id);
        ws.send(Message::Binary(join)).await.unwrap();
    }

    advance(Duration::from_secs(4)).await;

    let (mut ws, _) = connect_async(&url).await.unwrap();
    let mut join = vec![0x00, 0x69, 0x03];
    join.extend_from_slice(&session_id);
    ws.send(Message::Binary(join)).await.unwrap();

    let mut token = [0u8; 32];
    if let Some(Ok(Message::Binary(data))) = ws.next().await {
        token.copy_from_slice(&data[1..33]);
    }

    advance(Duration::from_secs(2)).await;

    drop(ws);
    advance(Duration::from_secs(6)).await;

    let (mut ws, _) = connect_async(&url).await.unwrap();
    let mut join = vec![0x00, 0x69, 0x03];
    join.extend_from_slice(&session_id);
    ws.send(Message::Binary(join)).await.unwrap();

    let mut new_token = [0u8; 32];
    if let Some(Ok(Message::Binary(data))) = ws.next().await {
        new_token.copy_from_slice(&data[1..33]);
    }

    let (mut r_ws, _) = connect_async(&url).await.unwrap();
    let mut r_join = vec![0x00, 0x72, 0x03];
    r_join.extend_from_slice(&session_id);
    r_join.extend_from_slice(&new_token);
    r_ws.send(Message::Binary(r_join)).await.unwrap();
}

#[tokio::test]
async fn test_scenario_f_server_expiry() {
    std::env::set_var("BLINDWIRE_TEST_TTL", "1");

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("ws://{}", addr);

    tokio::spawn(async move {
        run_server(listener).await;
    });

    let (mut ws, _) = connect_async(&url).await.unwrap();
    let mut join = vec![0x00, 0x69, 0x03];
    join.extend_from_slice(&[0xF6u8; 32]);
    ws.send(Message::Binary(join)).await.unwrap();

    // Consume TOKEN_MINTED
    ws.next().await.unwrap().unwrap();

    sleep(Duration::from_secs(4)).await;

    if let Some(Ok(Message::Binary(data))) = ws.next().await {
        assert_eq!(data[0], 0x04); // EXPIRED
    } else {
        panic!("Expected EXPIRED notification");
    }

    while (ws.next().await).is_some() {}
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

    let mut v1_join = vec![0x00, 0x69, 0x01];
    v1_join.extend_from_slice(&[0x11u8; 32]);
    ws.send(Message::Binary(v1_join)).await.unwrap();

    if let Some(Ok(Message::Binary(data))) = ws.next().await {
        assert_eq!(data[0], 0x05); // ERROR
        assert_eq!(data[1], 0x06); // VERSION_MISMATCH
    } else {
        panic!("Expected VERSION_MISMATCH error for v1 client");
    }
    while (ws.next().await).is_some() {}

    let (mut ws2, _) = connect_async(&url).await.unwrap();
    let mut v2_bad_join = vec![0x00, 0x69, 0x02];
    v2_bad_join.extend_from_slice(&[0x22u8; 32]);
    ws2.send(Message::Binary(v2_bad_join)).await.unwrap();

    if let Some(Ok(Message::Binary(data))) = ws2.next().await {
        assert_eq!(data[0], 0x05); // ERROR
        assert_eq!(data[1], 0x06); // VERSION_MISMATCH
    } else {
        panic!("Expected VERSION_MISMATCH error for bad version byte");
    }
    while (ws2.next().await).is_some() {}

    let (mut ws3, _) = connect_async(&url).await.unwrap();
    let mut v3_good_join = vec![0x00, 0x69, 0x03];
    v3_good_join.extend_from_slice(&[0x33u8; 32]);
    ws3.send(Message::Binary(v3_good_join)).await.unwrap();

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

#[tokio::test]
async fn signaling_v3_is_required() {
    let url = start_test_server().await;

    let (mut v2, _) = connect_async(&url).await.unwrap();
    let mut v2_join = vec![0x00, 0x69, 0x02];
    v2_join.extend_from_slice(&[0x71; 32]);
    v2.send(Message::Binary(v2_join)).await.unwrap();
    assert_eq!(next_binary(&mut v2).await, vec![0x05, 0x06]);

    let (_v3, token) = connect_initiator(&url, [0x72; 32], 0x03).await;
    assert_ne!(token, [0; 32]);
}

#[tokio::test]
async fn relay_preserves_production_frame_wire_format() {
    let url = start_test_server().await;
    let (mut initiator, mut responder, _) = connect_pair(&url, [0x73; 32]).await;
    let envelope = wrap_relay(Frame::handshake(vec![0xA5, 0x5A]).unwrap());

    initiator
        .send(Message::Binary(envelope.clone()))
        .await
        .unwrap();

    assert_eq!(next_binary(&mut responder).await, envelope);
}

#[tokio::test]
async fn one_completion_does_not_confirm_or_consume_invite() {
    let url = start_test_server().await;
    let session_id = [0x74; 32];
    let (mut initiator, mut responder, token) = connect_pair(&url, session_id).await;

    initiator.send(Message::Binary(vec![0x03])).await.unwrap();
    assert_no_binary(&mut initiator).await;
    assert_no_binary(&mut responder).await;

    drop(responder);
    assert_eq!(next_binary(&mut initiator).await, vec![0x03]);

    let mut replacement = connect_responder(&url, session_id, token, 0x03).await;
    assert_eq!(next_binary(&mut initiator).await, vec![0x02]);
    assert_eq!(next_binary(&mut replacement).await, vec![0x02]);
}

#[tokio::test]
async fn both_completions_confirm_once_and_consume_invite() {
    let url = start_test_server().await;
    let session_id = [0x75; 32];
    let (mut initiator, mut responder, token) = connect_pair(&url, session_id).await;

    initiator.send(Message::Binary(vec![0x03])).await.unwrap();
    responder.send(Message::Binary(vec![0x03])).await.unwrap();
    assert_eq!(next_binary(&mut initiator).await, vec![0x07]);
    assert_eq!(next_binary(&mut responder).await, vec![0x07]);

    initiator.send(Message::Binary(vec![0x03])).await.unwrap();
    assert_no_binary(&mut initiator).await;
    assert_no_binary(&mut responder).await;

    let mut replay = connect_responder(&url, session_id, token, 0x03).await;
    assert_eq!(next_binary(&mut replay).await, vec![0x05, 0x04]);
}

#[tokio::test]
async fn confirmed_room_rejects_replacement_initiator() {
    let url = start_test_server().await;
    let session_id = [0x7B; 32];
    let (mut initiator, mut responder, _) = connect_pair(&url, session_id).await;

    initiator.send(Message::Binary(vec![0x03])).await.unwrap();
    responder.send(Message::Binary(vec![0x03])).await.unwrap();
    assert_eq!(next_binary(&mut initiator).await, vec![0x07]);
    assert_eq!(next_binary(&mut responder).await, vec![0x07]);

    drop(initiator);
    assert_eq!(next_binary(&mut responder).await, vec![0x03]);

    let (mut replacement, _) = connect_async(&url).await.unwrap();
    let mut join = vec![0x00, 0x69, 0x03];
    join.extend_from_slice(&session_id);
    replacement.send(Message::Binary(join)).await.unwrap();

    assert_eq!(
        next_binary(&mut replacement).await,
        vec![0x05, 0x01],
        "a confirmed room must not mint a replacement invitation"
    );
}

#[tokio::test]
async fn responder_disconnect_clears_both_completion_flags() {
    let url = start_test_server().await;
    let session_id = [0x76; 32];
    let (mut initiator, mut responder, token) = connect_pair(&url, session_id).await;

    initiator.send(Message::Binary(vec![0x03])).await.unwrap();
    drop(responder);
    assert_eq!(next_binary(&mut initiator).await, vec![0x03]);

    responder = connect_responder(&url, session_id, token, 0x03).await;
    assert_eq!(next_binary(&mut initiator).await, vec![0x02]);
    assert_eq!(next_binary(&mut responder).await, vec![0x02]);

    responder.send(Message::Binary(vec![0x03])).await.unwrap();
    assert_no_binary(&mut initiator).await;
    assert_no_binary(&mut responder).await;

    initiator.send(Message::Binary(vec![0x03])).await.unwrap();
    assert_eq!(next_binary(&mut initiator).await, vec![0x07]);
    assert_eq!(next_binary(&mut responder).await, vec![0x07]);
}

#[tokio::test]
async fn initiator_disconnect_invalidates_incomplete_room() {
    let url = start_test_server().await;
    let session_id = [0x77; 32];
    let (initiator, mut responder, token) = connect_pair(&url, session_id).await;

    responder.send(Message::Binary(vec![0x03])).await.unwrap();
    drop(initiator);
    assert_eq!(next_binary(&mut responder).await, vec![0x03]);
    drop(responder);

    let mut replay = connect_responder(&url, session_id, token, 0x03).await;
    assert_eq!(next_binary(&mut replay).await, vec![0x05, 0x04]);
}

#[tokio::test]
async fn completion_payload_is_rejected() {
    let url = start_test_server().await;
    let (mut initiator, mut responder, _) = connect_pair(&url, [0x78; 32]).await;

    responder
        .send(Message::Binary(vec![0x03, 0x00]))
        .await
        .unwrap();
    assert_eq!(next_binary(&mut responder).await, vec![0x05, 0x02]);
    assert_eq!(next_binary(&mut initiator).await, vec![0x03]);
}

#[tokio::test]
async fn completion_before_responder_reservation_is_rejected() {
    let url = start_test_server().await;
    let (mut initiator, _) = connect_initiator(&url, [0x79; 32], 0x03).await;

    initiator.send(Message::Binary(vec![0x03])).await.unwrap();
    assert_eq!(next_binary(&mut initiator).await, vec![0x05, 0x04]);
}
