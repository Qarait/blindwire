#![allow(clippy::uninlined_format_args)]

//! End-to-end integration tests for blindwire-transport with blindwire-server.

use blindwire_server::run_server;
use blindwire_transport::{SecureSession, TransportConfig, TransportError};
use futures_util::{SinkExt, StreamExt};
use std::time::Duration;
use tokio::net::TcpListener;
use tokio_tungstenite::{connect_async, tungstenite::protocol::Message};

async fn start_server() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind failed");
    let addr = listener.local_addr().expect("no local addr");
    tokio::spawn(async move {
        run_server(listener).await;
    });
    format!("ws://{addr}")
}

/// Full public-API flow: confirmation gates success, messages work, and the invite is consumed.
#[tokio::test]
async fn test_full_session_e2e() {
    let url = start_server().await;
    let session_id = [0xE2u8; 32];
    let initiator_url = url.clone();
    let responder_url = url.clone();
    let (tx, rx) = tokio::sync::oneshot::channel();

    let initiator_handle = tokio::spawn(async move {
        let config = TransportConfig::initiator(initiator_url, session_id).with_insecure_dev();
        let (mut session, token) = SecureSession::connect(config).await?;
        tx.send(token.expect("initiator token"))
            .expect("send token");
        session.handshake().await?;
        Ok::<_, TransportError>(session)
    });

    let token = rx.await.expect("receive token");
    let responder_handle = tokio::spawn(async move {
        let config =
            TransportConfig::responder(responder_url, session_id, token).with_insecure_dev();
        let (mut session, _) = SecureSession::connect(config).await?;
        session.handshake().await?;
        Ok::<_, TransportError>(session)
    });

    let (initiator, responder) = tokio::time::timeout(Duration::from_secs(5), async {
        let initiator = initiator_handle.await.expect("initiator task")?;
        let responder = responder_handle.await.expect("responder task")?;
        Ok::<_, TransportError>((initiator, responder))
    })
    .await
    .expect("handshake timed out")
    .expect("handshake failed");
    let (mut initiator, mut responder) = (initiator, responder);

    assert_eq!(initiator.fingerprint(), responder.fingerprint());

    let replay = TransportConfig::responder(url.clone(), session_id, token).with_insecure_dev();
    assert!(matches!(
        SecureSession::connect(replay).await,
        Err(TransportError::UnexpectedResponse(0x04))
    ));

    let (sent, received) = tokio::join!(
        initiator.send_text("Hello from initiator!"),
        responder.recv()
    );
    sent.expect("initiator send failed");
    assert_eq!(
        received
            .expect("responder receive failed")
            .as_str()
            .expect("utf8"),
        "Hello from initiator!"
    );

    let (sent, received) = tokio::join!(responder.send_text("Hello back!"), initiator.recv());
    sent.expect("responder send failed");
    assert_eq!(
        received
            .expect("initiator receive failed")
            .as_str()
            .expect("utf8"),
        "Hello back!"
    );

    initiator.burn();
    responder.burn();
}

/// A responder can vanish after Noise starts; the initiator must reset and accept a fresh peer.
#[tokio::test]
async fn initiator_restarts_noise_after_unconfirmed_responder_loss() {
    let url = start_server().await;
    let session_id = [0xE3u8; 32];
    let config = TransportConfig::initiator(url.clone(), session_id).with_insecure_dev();
    let (mut initiator, token) = SecureSession::connect(config)
        .await
        .expect("initiator connect");
    let token = token.expect("initiator token");

    let initiator_handle = tokio::spawn(async move {
        let result = initiator.handshake().await;
        (initiator, result)
    });

    let (mut interrupted, _) = connect_async(&url).await.expect("raw responder connect");
    let mut join = vec![0x00, 0x72, 0x03];
    join.extend_from_slice(&session_id);
    join.extend_from_slice(&token);
    interrupted
        .send(Message::Binary(join))
        .await
        .expect("raw responder join");

    loop {
        let packet = tokio::time::timeout(Duration::from_secs(2), interrupted.next())
            .await
            .expect("initiator did not start Noise")
            .expect("raw responder stream ended")
            .expect("raw responder receive failed")
            .into_data();
        if packet.first() == Some(&0x01) {
            break;
        }
    }
    drop(interrupted);

    let replacement_config = TransportConfig::responder(url, session_id, token).with_insecure_dev();
    let (mut replacement, _) = SecureSession::connect(replacement_config)
        .await
        .expect("replacement connect");
    let replacement_handle = tokio::spawn(async move {
        let result = replacement.handshake().await;
        (replacement, result)
    });

    let (initiator_join, replacement_join) = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(initiator_handle, replacement_handle)
    })
    .await
    .expect("replacement handshake timed out");
    let (initiator, initiator_result) = initiator_join.expect("initiator task");
    let (replacement, replacement_result) = replacement_join.expect("replacement task");
    initiator_result.expect("initiator retry failed");
    replacement_result.expect("replacement handshake failed");
    assert_eq!(initiator.fingerprint(), replacement.fingerprint());
}

#[tokio::test]
async fn handshake_has_one_thirty_second_deadline() {
    let url = start_server().await;
    let config = TransportConfig::initiator(url, [0xE4; 32]).with_insecure_dev();
    let (mut initiator, _) = SecureSession::connect(config)
        .await
        .expect("initiator connect");

    tokio::time::pause();
    let handle = tokio::spawn(async move { initiator.handshake().await });
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(31)).await;
    tokio::task::yield_now().await;

    if !handle.is_finished() {
        handle.abort();
        panic!("handshake did not honor a single 30-second deadline");
    }
    assert!(matches!(
        handle.await.expect("handshake task"),
        Err(TransportError::Timeout)
    ));
}

/// Test Rate Limiting: 5 active connections per IP and 10 JOINs per minute limit.
#[tokio::test]
async fn test_rate_limiting() {
    let url = start_server().await;
    let session_id = [0xAAu8; 32];
    let mut handles = Vec::new();

    for i in 0..5 {
        let url_clone = url.clone();
        let mut unique_session_id = session_id;
        unique_session_id[0] = i;
        handles.push(tokio::spawn(async move {
            let config =
                TransportConfig::initiator(url_clone, unique_session_id).with_insecure_dev();
            if let Ok((mut session, _)) = SecureSession::connect(config).await {
                let _ = session.handshake().await;
            }
        }));
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    let mut sixth_id = session_id;
    sixth_id[0] = 99;
    let sixth = TransportConfig::initiator(url.clone(), sixth_id).with_insecure_dev();
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(5), SecureSession::connect(sixth)).await,
        Ok(Err(TransportError::RateLimitExceeded))
    ));

    for handle in handles {
        handle.abort();
    }
    tokio::time::sleep(Duration::from_millis(500)).await;

    let mut burst_handles = Vec::new();
    for i in 0..10 {
        let url_clone = url.clone();
        burst_handles.push(tokio::spawn(async move {
            let config = TransportConfig::initiator(url_clone, session_id).with_insecure_dev();
            let _ = SecureSession::connect(config).await;
        }));
        tokio::time::sleep(Duration::from_millis(50)).await;
        if (i + 1) % 4 == 0 {
            if let Some(handle) = burst_handles.pop() {
                handle.abort();
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    let eleventh = TransportConfig::initiator(url, session_id).with_insecure_dev();
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(2), SecureSession::connect(eleventh)).await,
        Ok(Err(TransportError::RateLimitExceeded))
    ));

    for handle in burst_handles {
        handle.abort();
    }
}
