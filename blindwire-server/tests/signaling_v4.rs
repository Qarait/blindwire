#![allow(clippy::uninlined_format_args)]

use futures_util::{SinkExt, StreamExt};
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio_tungstenite::{
    connect_async, tungstenite::protocol::Message, MaybeTlsStream, WebSocketStream,
};

type TestWebSocket = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

async fn start_test_server() -> (String, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        blindwire_server::run_server(listener).await;
    });
    (format!("ws://{address}"), task)
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

async fn connect_v4_initiator(url: &str, room: [u8; 32]) -> (TestWebSocket, [u8; 32]) {
    let (mut ws, _) = connect_async(url).await.unwrap();
    let mut join = vec![0x00, b'i', 0x04];
    join.extend_from_slice(&room);
    ws.send(Message::Binary(join)).await.unwrap();

    let packet = next_binary(&mut ws).await;
    assert_eq!(packet[0], 0x06);
    assert_eq!(packet.len(), 33);
    let mut token = [0_u8; 32];
    token.copy_from_slice(&packet[1..]);
    (ws, token)
}

async fn connect_v4_responder(url: &str, room: [u8; 32], token: [u8; 32]) -> TestWebSocket {
    let (mut ws, _) = connect_async(url).await.unwrap();
    let mut join = vec![0x00, b'r', 0x04];
    join.extend_from_slice(&room);
    join.extend_from_slice(&token);
    ws.send(Message::Binary(join)).await.unwrap();
    ws
}

async fn connect_confirmed_pair(url: &str, room: [u8; 32]) -> (TestWebSocket, TestWebSocket) {
    let (mut initiator, token) = connect_v4_initiator(url, room).await;
    let mut responder = connect_v4_responder(url, room, token).await;
    assert_eq!(next_binary(&mut initiator).await, vec![0x02]);
    assert_eq!(next_binary(&mut responder).await, vec![0x02]);
    initiator.send(Message::Binary(vec![0x03])).await.unwrap();
    responder.send(Message::Binary(vec![0x03])).await.unwrap();
    assert_eq!(next_binary(&mut initiator).await, vec![0x07]);
    assert_eq!(next_binary(&mut responder).await, vec![0x07]);
    (initiator, responder)
}

#[tokio::test]
async fn v4_join_token_peer_join_and_two_sided_confirmation() {
    let (url, server_task) = start_test_server().await;
    let (mut initiator, token) = connect_v4_initiator(&url, [0x61; 32]).await;
    let mut responder = connect_v4_responder(&url, [0x61; 32], token).await;

    assert_eq!(next_binary(&mut initiator).await, vec![0x02]);
    assert_eq!(next_binary(&mut responder).await, vec![0x02]);
    initiator.send(Message::Binary(vec![0x03])).await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(100), responder.next())
            .await
            .is_err()
    );
    responder.send(Message::Binary(vec![0x03])).await.unwrap();
    assert_eq!(next_binary(&mut initiator).await, vec![0x07]);
    assert_eq!(next_binary(&mut responder).await, vec![0x07]);
    server_task.abort();
}

#[tokio::test]
async fn v4_relay_is_opaque_and_preserves_frame_bytes() {
    let (url, server_task) = start_test_server().await;
    let (mut initiator, mut responder) = connect_confirmed_pair(&url, [0x62; 32]).await;
    let opaque = vec![0x01, 0x00, 0x04, 0xde, 0xad, 0xbe, 0xef];
    initiator
        .send(Message::Binary(opaque.clone()))
        .await
        .unwrap();
    assert_eq!(next_binary(&mut responder).await, opaque);
    server_task.abort();
}

#[tokio::test]
async fn v4_malformed_packet_gets_one_error_and_terminates() {
    let (url, server_task) = start_test_server().await;
    let (mut initiator, token) = connect_v4_initiator(&url, [0x63; 32]).await;
    let mut responder = connect_v4_responder(&url, [0x63; 32], token).await;
    let _ = next_binary(&mut initiator).await;
    let _ = next_binary(&mut responder).await;

    initiator
        .send(Message::Binary(vec![0x01, 0x00, 0x00]))
        .await
        .unwrap();
    assert_eq!(next_binary(&mut initiator).await, vec![0x05, 0x02]);
    assert!(
        tokio::time::timeout(Duration::from_secs(1), initiator.next())
            .await
            .is_ok()
    );
    server_task.abort();
}

#[tokio::test]
async fn v4_recovery_registration_requires_confirmation() {
    let (url, server_task) = start_test_server().await;
    let (mut initiator, mut responder) = connect_confirmed_pair(&url, [0x64; 32]).await;
    initiator
        .send(Message::Binary([vec![0x04], vec![0x71; 32]].concat()))
        .await
        .unwrap();
    assert_eq!(next_binary(&mut initiator).await, vec![0x08]);
    responder
        .send(Message::Binary([vec![0x04], vec![0x72; 32]].concat()))
        .await
        .unwrap();
    assert_eq!(next_binary(&mut responder).await, vec![0x08]);
    server_task.abort();
}

#[tokio::test]
async fn v4_burn_notifies_both_roles_and_blocks_future_packets() {
    let (url, server_task) = start_test_server().await;
    let (mut initiator, mut responder) = connect_confirmed_pair(&url, [0x65; 32]).await;
    initiator.send(Message::Binary(vec![0x06])).await.unwrap();
    assert_eq!(next_binary(&mut responder).await, vec![0x0b]);
    assert_eq!(next_binary(&mut initiator).await, vec![0x0b]);
    server_task.abort();
}
