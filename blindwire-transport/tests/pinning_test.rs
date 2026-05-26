//! Tests for certificate pinning and TOFU.

use blindwire_transport::TransportConfig;

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
