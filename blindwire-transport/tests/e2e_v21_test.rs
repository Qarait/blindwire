#![allow(clippy::uninlined_format_args)]

use blindwire_server::run_server;
use blindwire_transport::{SecureSessionV21, SessionEventV21, TransportConfig};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

async fn start_test_server() -> (String, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        run_server(listener).await;
    });
    (format!("ws://{address}"), task)
}

async fn connect_pair(
    room: [u8; 32],
) -> (
    blindwire_transport::SecureSessionV21,
    blindwire_transport::SecureSessionV21,
    JoinHandle<()>,
) {
    let (url, server_task) = start_test_server().await;
    let (initiator, token) = SecureSessionV21::connect_initial(
        TransportConfig::initiator(&url, room).with_insecure_dev(),
    )
    .await
    .unwrap();
    let (responder, responder_token) = SecureSessionV21::connect_initial(
        TransportConfig::responder(&url, room, token.unwrap()).with_insecure_dev(),
    )
    .await
    .unwrap();
    assert!(responder_token.is_none());
    (initiator, responder, server_task)
}

async fn handshake_pair(
    room: [u8; 32],
) -> (
    blindwire_transport::SecureSessionV21,
    blindwire_transport::SecureSessionV21,
    JoinHandle<()>,
) {
    let (mut initiator, mut responder, server_task) = connect_pair(room).await;
    let (initiator_result, responder_result) =
        tokio::join!(initiator.handshake(), responder.handshake());
    initiator_result.unwrap();
    responder_result.unwrap();
    assert_eq!(
        initiator.recv_event().await.unwrap(),
        SessionEventV21::VerificationReady
    );
    assert_eq!(
        responder.recv_event().await.unwrap(),
        SessionEventV21::VerificationReady
    );
    (initiator, responder, server_task)
}

#[tokio::test]
async fn initial_handshake_exposes_verification_ready_to_both_peers() {
    let (url, server_task) = start_test_server().await;
    let room = [0x61; 32];

    let (mut initiator, token) = SecureSessionV21::connect_initial(
        TransportConfig::initiator(&url, room).with_insecure_dev(),
    )
    .await
    .unwrap();

    let (mut responder, responder_token) = SecureSessionV21::connect_initial(
        TransportConfig::responder(&url, room, token.unwrap()).with_insecure_dev(),
    )
    .await
    .unwrap();
    assert!(responder_token.is_none());

    let (initiator_result, responder_result) =
        tokio::join!(initiator.handshake(), responder.handshake());
    initiator_result.unwrap();
    responder_result.unwrap();

    assert_eq!(
        initiator.recv_event().await.unwrap(),
        SessionEventV21::VerificationReady
    );
    assert_eq!(
        responder.recv_event().await.unwrap(),
        SessionEventV21::VerificationReady
    );
    server_task.abort();
}

#[tokio::test]
async fn verification_is_two_sided_and_text_is_acknowledged() {
    let (mut initiator, _responder, server_task) = handshake_pair([0x62; 32]).await;

    assert!(matches!(
        initiator.send_text("blocked until verification").await,
        Err(blindwire_transport::TransportError::VerificationRequired)
    ));
    server_task.abort();
}

#[tokio::test]
async fn verified_peers_exchange_text_and_ack() {
    let (mut initiator, mut responder, server_task) = handshake_pair([0x63; 32]).await;

    let (initiator_result, responder_result) = tokio::join!(
        initiator.confirm_user_verified(),
        responder.confirm_user_verified()
    );
    initiator_result.unwrap();
    responder_result.unwrap();

    let (initiator_event, responder_event) =
        tokio::join!(initiator.recv_event(), responder.recv_event());
    assert_eq!(initiator_event.unwrap(), SessionEventV21::PeerVerified);
    assert_eq!(responder_event.unwrap(), SessionEventV21::PeerVerified);

    let id = initiator
        .send_text("hello over Protocol 2.1")
        .await
        .unwrap();
    assert_eq!(
        responder.recv_event().await.unwrap(),
        SessionEventV21::TextReceived {
            id,
            text: "hello over Protocol 2.1".to_owned()
        }
    );
    assert_eq!(
        initiator.recv_event().await.unwrap(),
        SessionEventV21::MessageAcknowledged { id }
    );
    server_task.abort();
}

#[tokio::test]
async fn remote_burn_is_reported_as_a_terminal_event() {
    let (mut initiator, mut responder, server_task) = handshake_pair([0x64; 32]).await;

    let (initiator_result, responder_result) = tokio::join!(
        initiator.confirm_user_verified(),
        responder.confirm_user_verified()
    );
    initiator_result.unwrap();
    responder_result.unwrap();
    let (initiator_event, responder_event) =
        tokio::join!(initiator.recv_event(), responder.recv_event());
    assert_eq!(initiator_event.unwrap(), SessionEventV21::PeerVerified);
    assert_eq!(responder_event.unwrap(), SessionEventV21::PeerVerified);

    initiator.burn().await.unwrap();
    assert_eq!(
        responder.recv_event().await.unwrap(),
        SessionEventV21::RoomBurned
    );
    assert!(matches!(
        responder.recv_event().await,
        Err(blindwire_transport::TransportError::SessionTerminated)
    ));
    server_task.abort();
}

#[tokio::test]
async fn authenticated_resume_reestablishes_fresh_session_state() {
    let room = [0x65; 32];
    let (url, server_task) = start_test_server().await;
    let initiator_config = TransportConfig::initiator(&url, room).with_insecure_dev();
    let (mut initiator, token) = SecureSessionV21::connect_initial(initiator_config)
        .await
        .unwrap();
    let (mut responder, responder_token) = SecureSessionV21::connect_initial(
        TransportConfig::responder(&url, room, token.unwrap()).with_insecure_dev(),
    )
    .await
    .unwrap();
    assert!(responder_token.is_none());

    let (initiator_result, responder_result) =
        tokio::join!(initiator.handshake(), responder.handshake());
    initiator_result.unwrap();
    responder_result.unwrap();
    assert_eq!(
        initiator.recv_event().await.unwrap(),
        SessionEventV21::VerificationReady
    );
    assert_eq!(
        responder.recv_event().await.unwrap(),
        SessionEventV21::VerificationReady
    );
    let (initiator_result, responder_result) = tokio::join!(
        initiator.confirm_user_verified(),
        responder.confirm_user_verified()
    );
    initiator_result.unwrap();
    responder_result.unwrap();
    let (initiator_event, responder_event) =
        tokio::join!(initiator.recv_event(), responder.recv_event());
    assert_eq!(initiator_event.unwrap(), SessionEventV21::PeerVerified);
    assert_eq!(responder_event.unwrap(), SessionEventV21::PeerVerified);

    let snapshot = initiator.recovery_snapshot().unwrap();
    let resume_config = TransportConfig::initiator(&url, room).with_insecure_dev();
    let (resume_result, peer_result) = tokio::join!(
        SecureSessionV21::resume(resume_config, snapshot),
        responder.recv_event()
    );
    let mut recovered = resume_result.unwrap();
    assert_eq!(peer_result.unwrap(), SessionEventV21::Recovering);
    assert_eq!(
        recovered.recv_event().await.unwrap(),
        SessionEventV21::Recovering
    );
    assert_eq!(
        recovered.recv_event().await.unwrap(),
        SessionEventV21::Recovered
    );
    assert!(matches!(
        recovered.send_text("re-verify first").await,
        Err(blindwire_transport::TransportError::VerificationRequired)
    ));
    server_task.abort();
}

#[tokio::test]
async fn recovery_snapshot_is_bound_to_its_role_and_room() {
    let (mut initiator, _responder, server_task) = handshake_pair([0x66; 32]).await;
    let snapshot = initiator.recovery_snapshot().unwrap();

    let wrong_room = TransportConfig::initiator("ws://127.0.0.1:1", [0x67; 32]).with_insecure_dev();
    assert!(matches!(
        SecureSessionV21::resume(wrong_room, snapshot).await,
        Err(blindwire_transport::TransportError::RecoveryUnavailable)
    ));
    server_task.abort();
}

#[tokio::test]
async fn recovery_snapshot_rejects_a_role_change() {
    let (mut initiator, _responder, server_task) = handshake_pair([0x68; 32]).await;
    let snapshot = initiator.recovery_snapshot().unwrap();
    let wrong_role =
        TransportConfig::responder("ws://127.0.0.1:1", [0x68; 32], [0; 32]).with_insecure_dev();

    assert!(matches!(
        SecureSessionV21::resume(wrong_role, snapshot).await,
        Err(blindwire_transport::TransportError::RecoveryUnavailable)
    ));
    server_task.abort();
}
