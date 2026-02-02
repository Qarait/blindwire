//! End-to-end integration test for blindwire-transport with blindwire-server.

use blindwire_server::run_server;
use blindwire_transport::{SecureSession, TransportConfig};
use tokio::net::TcpListener;
use std::time::Duration;

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

    let (r_send, i_recv) = tokio::join!(
        responder.send_text("Hello back!"),
        initiator.recv()
    );
    r_send.expect("responder send failed");
    let msg = i_recv.expect("initiator recv failed");
    assert_eq!(msg.as_str().expect("utf8"), "Hello back!");
    println!("Initiator received: {}", msg.as_str().unwrap());

    // 6. Clean termination
    initiator.burn();
    responder.burn();
    println!("Test passed!");
}
