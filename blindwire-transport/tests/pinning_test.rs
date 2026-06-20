//! Tests for certificate pinning and TOFU.

use blindwire_transport::{reset_server_pin, PinResetError, TransportConfig};

// Note: Real WSS testing requires certificates which is complex for unit tests.
// We will test the logic by verifying that the config respects the pinning path
// and that the verifier correctly handles official vs custom domains.

#[tokio::test]
async fn test_config_pinning_path() {
    let tmp_dir = tempfile::tempdir().unwrap();
    let pins_path = tmp_dir.path().join("pins.txt");

    let config = TransportConfig::initiator("ws://localhost:8080", [0u8; 32])
        .with_pins_path(pins_path.clone());
    assert_eq!(config.pins_path, Some(pins_path));
}

#[test]
fn reset_server_pin_is_scoped_and_durable() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("pins.txt");
    let hash_a = "aa".repeat(32);
    let hash_b = "bb".repeat(32);
    std::fs::write(
        &path,
        format!("custom.example:{hash_a}\nother.example:{hash_b}\n"),
    )
    .unwrap();

    assert!(reset_server_pin(&path, "wss://custom.example:443/path").unwrap());
    let persisted = std::fs::read_to_string(&path).unwrap();
    assert!(!persisted.contains("custom.example"));
    assert!(persisted.contains("other.example"));
    assert!(!reset_server_pin(&path, "wss://custom.example").unwrap());
}

#[test]
fn reset_server_pin_rejects_the_official_relay() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("pins.txt");
    std::fs::write(&path, format!("relay.blindwire.net:{}\n", "aa".repeat(32))).unwrap();

    let error = reset_server_pin(&path, "wss://relay.blindwire.net")
        .expect_err("official relay pins are compile-time policy");

    assert!(matches!(error, PinResetError::OfficialRelay));
}
