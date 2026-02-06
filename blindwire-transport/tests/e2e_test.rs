//! End-to-end integration test for blindwire-transport with blindwire-server.

use blindwire_server::run_server;
use blindwire_transport::{SecureSession, TransportConfig, TransportError};
use std::time::Duration;
use tokio::net::TcpListener;

/// Full end-to-end test: connect, handshake, exchange messages.
#[tokio::test]
async fn test_full_session_e2e() {
    // 1. Start server
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind failed");
    let addr = listener.local_addr().expect("no local addr");
    let url = format!("ws://{}", addr);
    println!("Server URL: {}", url);

    tokio::spawn(async move {
        run_server(listener).await;
    });

    // Give server time to start
    tokio::time::sleep(Duration::from_millis(100)).await;

    // 2. Create session ID
    let session_id = [0xE2u8; 32];

    // 3. Initiator connects FIRST (it will wait for peer in wait_for_peer())
    //    Then responder connects, which triggers PEER_JOINED to initiator
    //    Then both do handshake
    let initiator_url = url.clone();
    let responder_url = url.clone();

    let initiator_handle = tokio::spawn(async move {
        println!("Initiator connecting...");
        let config = TransportConfig::initiator(initiator_url, session_id).with_insecure_dev();
        let result = SecureSession::connect(config).await;
        if let Err(ref e) = result {
            println!("Initiator connect failed: {:?}", e);
        } else {
            println!("Initiator connect success!");
        }
        result
    });

    // Small delay to ensure initiator is waiting
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Spawn responder - this triggers PEER_JOINED to initiator
    let responder_handle = tokio::spawn(async move {
        println!("Responder connecting...");
        let config = TransportConfig::responder(responder_url, session_id).with_insecure_dev();
        let result = SecureSession::connect(config).await;
        if let Err(ref e) = result {
            println!("Responder connect failed: {:?}", e);
        } else {
            println!("Responder connect success!");
        }
        result
    });

    // Wait for both
    let (i_result, r_result) = tokio::join!(initiator_handle, responder_handle);

    let mut initiator = i_result.expect("task panic").expect("initiator failed");
    let mut responder = r_result.expect("task panic").expect("responder failed");

    println!("Both connected!");

    // 4. Verify fingerprints match
    let i_fp = initiator.fingerprint().expect("no fingerprint");
    let r_fp = responder.fingerprint().expect("no fingerprint");
    println!("Initiator fingerprint: {}", i_fp);
    println!("Responder fingerprint: {}", r_fp);
    assert_eq!(i_fp, r_fp, "Fingerprints must match");

    // 5. Bidirectional message exchange
    println!("Testing bidirectional exchange...");

    let (i_send, r_recv) = tokio::join!(
        initiator.send_text("Hello from initiator!"),
        responder.recv()
    );
    i_send.expect("initiator send failed");
    let msg = r_recv.expect("responder recv failed");
    assert_eq!(msg.as_str().expect("utf8"), "Hello from initiator!");
    println!("Responder received: {}", msg.as_str().unwrap());

    let (r_send, i_recv) = tokio::join!(responder.send_text("Hello back!"), initiator.recv());
    r_send.expect("responder send failed");
    let msg = i_recv.expect("initiator recv failed");
    assert_eq!(msg.as_str().expect("utf8"), "Hello back!");
    println!("Initiator received: {}", msg.as_str().unwrap());

    // 6. Clean termination
    initiator.burn();
    responder.burn();
    println!("Test passed!");
}

/// Test Rate Limiting: 5 active connections per IP and 10 JOINs per minute limit.
#[tokio::test]
async fn test_rate_limiting() {
    // 1. Start server
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind failed");
    let addr = listener.local_addr().expect("no local addr");
    let url = format!("ws://{}", addr);

    tokio::spawn(async move {
        run_server(listener).await;
    });

    // Give server time to start
    tokio::time::sleep(Duration::from_millis(100)).await;

    let session_id = [0xAAu8; 32];

    // Part A: Test MAX_CONN_PER_IP (5)
    println!("Testing connection limit (5)...");
    let mut handles = Vec::new();
    for i in 0..5 {
        let url_clone = url.clone();
        let handle = tokio::spawn(async move {
            let config = TransportConfig::responder(url_clone, session_id).with_insecure_dev();
            // This will block waiting for a handshake, which is fine for held connections
            let _ = SecureSession::connect(config).await;
        });
        handles.push(handle);
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // 6th connection should fail with RateLimitExceeded
    let config = TransportConfig::initiator(url.clone(), session_id).with_insecure_dev();
    let res = SecureSession::connect(config).await;
    match res {
        Err(TransportError::RateLimitExceeded) => {
            println!("Correctly received RateLimitExceeded on 6th connection (at accept)");
        }
        res => panic!("Expected RateLimitExceeded on 6th connection, got {:?}", res),
    }

    // Part B: Test BURST limit (10 joins)
    // We need to drop the previous connections first to clear the IP counter
    drop(handles);
    tokio::time::sleep(Duration::from_millis(500)).await; // Wait for server to detect dead conns

    println!("Testing burst limit (10 JOINs/min)...");
    // We send 10 JOINs. Each will succeed but stay pending.
    let mut burst_handles = Vec::new();
    for i in 0..10 {
        let url_clone = url.clone();
        let h = tokio::spawn(async move {
            let config = TransportConfig::initiator(url_clone, session_id).with_insecure_dev();
            let _ = SecureSession::connect(config).await;
        });
        burst_handles.push(h);
        tokio::time::sleep(Duration::from_millis(50)).await;
        // The server limit is 5 conns, so we must drop some as we go to keep making connections
        if (i + 1) % 4 == 0 {
             tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    // 11th JOIN attempt should fail with RateLimitExceeded
    let config = TransportConfig::initiator(url.clone(), session_id).with_insecure_dev();
    let res = SecureSession::connect(config).await;
    assert!(matches!(res, Err(TransportError::RateLimitExceeded)));
    println!("Correctly received RateLimitExceeded on 11th JOIN attempt");
}
