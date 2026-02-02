use blindwire_server::run_server;
use blindwire_core::state::{Session, SessionReceiveResult, SessionState};
use blindwire_core::frame::Frame;
use tokio::net::TcpListener;
use tokio_tungstenite::{connect_async, tungstenite::protocol::Message};
use futures_util::{SinkExt, StreamExt};
use std::time::Duration;

#[tokio::test]
async fn test_full_handshake_and_relay() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("ws://{}", addr);

    tokio::spawn(async move {
        run_server(listener).await;
    });

    // Clients
    let mut initiator_session = Session::new_initiator().unwrap();
    let mut responder_session = Session::new_responder().unwrap();
    let session_id = [0xAAu8; 32];
    
    // 1. Connect Initiator
    let (mut i_ws, _) = connect_async(&url).await.unwrap();
    let mut i_join = vec![0x00, 0x69]; // JOIN ('i')
    i_join.extend_from_slice(&session_id);
    i_ws.send(Message::Binary(i_join)).await.unwrap();
    
    // 2. Connect Responder
    let (mut r_ws, _) = connect_async(&url).await.unwrap();
    let mut r_join = vec![0x00, 0x72]; // JOIN ('r')
    r_join.extend_from_slice(&session_id);
    r_ws.send(Message::Binary(r_join)).await.unwrap();

    // 3. Perform Handshake
    // Initiator starts
    i_session_step(&mut initiator_session, &mut i_ws).await;
    
    // Loop until both ACTIVE
    for _ in 0..20 {
        if initiator_session.state() == SessionState::Active && responder_session.state() == SessionState::Active {
            break;
        }

        tokio::select! {
            msg = i_ws.next() => {
                if let Some(Ok(Message::Binary(data))) = msg {
                    process_client_msg(&mut initiator_session, &mut i_ws, data).await;
                }
            }
            msg = r_ws.next() => {
                if let Some(Ok(Message::Binary(data))) = msg {
                    process_client_msg(&mut responder_session, &mut r_ws, data).await;
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(100)) => {}
        }
    }

    assert_eq!(initiator_session.state(), SessionState::Active);
    assert_eq!(responder_session.state(), SessionState::Active);

    // 4. Relay Message
    let msg_text = "Hello integration test!";
    let frame = initiator_session.send_message(msg_text).unwrap();
    let mut relay_packet = vec![0x01]; // RELAY
    relay_packet.extend(frame.to_wire());
    i_ws.send(Message::Binary(relay_packet)).await.unwrap();

    // Responder receives
    if let Some(Ok(Message::Binary(data))) = r_ws.next().await {
        assert_eq!(data[0], 0x01); // RELAY
        let frame = Frame::parse(&data[1..]).unwrap();
        let res = responder_session.on_receive(frame).unwrap();
        if let SessionReceiveResult::Message(text) = res {
            assert_eq!(text, msg_text);
        } else {
            panic!("Expected message result");
        }
    } else {
        panic!("No message received");
    }
}

#[tokio::test]
async fn test_duplicate_role_join_rejection() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("ws://{}", addr);

    tokio::spawn(async move {
        run_server(listener).await;
    });

    let session_id = [0xBBu8; 32];
    
    // 1. Connect first initiator
    let (mut i1_ws, _) = connect_async(&url).await.unwrap();
    let mut i_join = vec![0x00, 0x69]; // JOIN ('i')
    i_join.extend_from_slice(&session_id);
    i1_ws.send(Message::Binary(i_join.clone())).await.unwrap();

    // 2. Connect second initiator (duplicate)
    let (mut i2_ws, _) = connect_async(&url).await.unwrap();
    i2_ws.send(Message::Binary(i_join)).await.unwrap();

    // 3. Second initiator should receive ERROR(0x01) and be closed
    if let Some(Ok(Message::Binary(data))) = i2_ws.next().await {
        assert_eq!(data[0], 0x05); // ERROR
        assert_eq!(data[1], 0x01); // ROLE_TAKEN
    } else {
        panic!("Expected Error packet");
    }
    
    // Check if i2_ws is closed
    assert!(i2_ws.next().await.is_none() || matches!(i2_ws.next().await, Some(Err(_))));
}

async fn i_session_step(session: &mut Session, ws: &mut (impl SinkExt<Message, Error = tokio_tungstenite::tungstenite::Error> + Unpin)) {
    if let Ok(frame) = session.start_handshake() {
        let mut data = vec![0x01]; // RELAY
        data.extend(frame.to_wire());
        ws.send(Message::Binary(data)).await.unwrap();
    }
}

async fn process_client_msg(session: &mut Session, ws: &mut (impl SinkExt<Message, Error = tokio_tungstenite::tungstenite::Error> + Unpin), data: Vec<u8>) {
    if data.is_empty() { return; }
    let opcode = data[0];
    if opcode != 0x01 { return; }
    
    let frame = Frame::parse(&data[1..]).unwrap();
    let res = session.on_receive(frame).unwrap();
    match res {
        SessionReceiveResult::HandshakeResponse(f) | SessionReceiveResult::HandshakeCompleteWithResponse(f) => {
            let mut relay = vec![0x01];
            relay.extend(f.to_wire());
            ws.send(Message::Binary(relay)).await.unwrap();
        }
        _ => {}
    }
}
