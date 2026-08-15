use blindwire_core::noise::Role;
use blindwire_core::recovery::{
    compute_resume_proof, derive_continuity_secret, ratchet_continuity_secret,
};
use blindwire_web_core::{generate_random_32, parse_invite, WebSession};
use serde::Deserialize;
use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_browser);

#[wasm_bindgen_test]
fn wasm_randomness_is_available() {
    let bytes = generate_random_32().unwrap();
    assert_eq!(bytes.len(), 32);
    assert!(bytes.iter().any(|byte| *byte != 0));
}

#[wasm_bindgen_test]
fn wasm_recovery_vectors_match_native_hex() {
    let room = [7; 32];
    let fingerprint = [3; 32];
    let secret = derive_continuity_secret(&room, &[1; 32], &[2; 32]).unwrap();
    let proof = compute_resume_proof(&secret, &room, Role::Initiator, 4, &fingerprint);
    assert_eq!(
        to_hex(&proof),
        "a5f0538f79da7af3819e28a68d875fe51d7c794aac973820cf6f6dbb36e124e5"
    );

    let ratcheted = ratchet_continuity_secret(secret, &room, 5, &[4; 32], &[5; 32]).unwrap();
    let ratcheted_proof = compute_resume_proof(&ratcheted, &room, Role::Responder, 5, &fingerprint);
    assert_eq!(
        to_hex(&ratcheted_proof),
        "30c3f3115ad6bd6c0a4f9b622ade1567426a9191babe2c47a6fa276a63ff61cb"
    );
}

#[derive(Debug, Deserialize)]
struct CallResult {
    events: Vec<TestEvent>,
    #[serde(default)]
    message_id: Option<Vec<u8>>,
}

#[derive(Debug, Deserialize)]
struct InviteDescriptor {
    room: String,
    token: String,
    expires_at: u64,
    relay_url: String,
    relay_pin: Option<String>,
    official_relay: bool,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum TestEvent {
    Outbound {
        frame: Vec<u8>,
    },
    Verification {
        emojis: Vec<String>,
        numeric: [u16; 7],
    },
    PeerVerified,
    Text {
        id: Vec<u8>,
        text: String,
    },
    Acknowledgement {
        id: Vec<u8>,
    },
    Recovering,
    Recovered,
    Burned,
}

#[wasm_bindgen_test]
fn parse_invite_returns_validated_worker_descriptor() {
    let exp = (js_sys::Date::now() as u64) + 3_600_000;
    let uri = format!(
        "blindwire://join?v=1&r=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&t=BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB&e={exp}"
    );
    let descriptor: InviteDescriptor =
        serde_wasm_bindgen::from_value(parse_invite(&uri).unwrap()).unwrap();
    assert_eq!(descriptor.room.len(), 43);
    assert_eq!(descriptor.token.len(), 43);
    assert_eq!(descriptor.expires_at, exp);
    assert_eq!(descriptor.relay_url, "wss://relay.blindwire.net/");
    assert_eq!(descriptor.relay_pin, None);
    assert!(descriptor.official_relay);
}

#[wasm_bindgen_test]
fn parse_invite_rejects_malformed_fields_with_a_public_error() {
    let exp = (js_sys::Date::now() as u64) + 3_600_000;
    let uri = format!(
        "blindwire://join?v=1&r=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&t=BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB&e={exp}&v=1"
    );
    assert_code(parse_invite(&uri), "INVITE_INVALID");
}

#[wasm_bindgen_test]
fn worker_checkpoint_does_not_consume_the_live_session() {
    let (mut initiator, _responder) = established_sessions();
    let snapshot = initiator.copy_worker_snapshot_for_storage(10_000).unwrap();
    assert!(!snapshot.is_empty());
    let result = call(initiator.send_text("still active").unwrap());
    assert!(result.message_id.is_some());
}

#[wasm_bindgen_test]
fn web_sessions_require_relay_and_two_sided_user_confirmation() {
    let room = [0x41; 32];
    let token = vec![0x52; 32];
    let mut initiator = WebSession::new(b'i', &room, None).unwrap();
    let mut responder = WebSession::new(b'r', &room, Some(token)).unwrap();

    let message_one = take_outbound(call(initiator.start_handshake().unwrap()));
    let message_two = take_outbound(call(responder.receive_frame(&message_one).unwrap()));
    let message_three = take_outbound(call(initiator.receive_frame(&message_two).unwrap()));
    let handshake_done = call(responder.receive_frame(&message_three).unwrap());
    assert!(handshake_done.events.is_empty());

    assert_code(initiator.send_text("too early"), "VERIFICATION_REQUIRED");

    let initiator_contribution =
        take_outbound(call(initiator.relay_handshake_confirmed().unwrap()));
    let responder_contribution =
        take_outbound(call(responder.relay_handshake_confirmed().unwrap()));
    let responder_sas = take_verification(call(
        responder.receive_frame(&initiator_contribution).unwrap(),
    ));
    let initiator_sas = take_verification(call(
        initiator.receive_frame(&responder_contribution).unwrap(),
    ));
    assert_eq!(initiator_sas, responder_sas);

    let initiator_verified = take_outbound(call(initiator.confirm_user_verified().unwrap()));
    let responder_verified = take_outbound(call(responder.confirm_user_verified().unwrap()));
    assert_code(
        initiator.send_text("still too early"),
        "VERIFICATION_REQUIRED",
    );

    assert!(has_peer_verified(call(
        responder.receive_frame(&initiator_verified).unwrap(),
    )));
    assert!(has_peer_verified(call(
        initiator.receive_frame(&responder_verified).unwrap(),
    )));

    let sent = call(initiator.send_text("hello from the browser").unwrap());
    let message_id = sent.message_id.clone().unwrap();
    let encrypted_text = take_outbound(sent);
    let received = call(responder.receive_frame(&encrypted_text).unwrap());
    assert!(has_text(&received, &message_id, "hello from the browser"));
    let acknowledgement = take_outbound(received);
    let acknowledged = call(initiator.receive_frame(&acknowledgement).unwrap());
    assert!(has_acknowledgement(&acknowledged, &message_id));
}

#[wasm_bindgen_test]
fn worker_snapshot_restores_only_into_authenticated_recovery() {
    let (mut initiator, mut responder) = established_sessions();
    let pending = call(initiator.send_text("pending across refresh").unwrap());
    let pending_id = pending.message_id.clone().unwrap();

    let snapshot = initiator
        .recovery_snapshot_for_worker_storage(10_000)
        .unwrap();
    let mut corrupted = snapshot.clone();
    let last = corrupted.len() - 1;
    corrupted[last] ^= 1;
    assert_restore_code(
        WebSession::restore_worker_snapshot(&corrupted, 9_000),
        "INVALID_SNAPSHOT",
    );
    assert_restore_code(
        WebSession::restore_worker_snapshot(&snapshot, 10_001),
        "SNAPSHOT_EXPIRED",
    );

    let mut restored = WebSession::restore_worker_snapshot(&snapshot, 9_000).unwrap();
    let one = take_outbound(call(restored.begin_recovery(1).unwrap()));
    let _ = responder.begin_recovery(1).unwrap();
    let two = take_outbound(call(responder.receive_frame(&one).unwrap()));
    let mut restored_handshake = outbound_frames(call(restored.receive_frame(&two).unwrap()));
    let three = restored_handshake.remove(0);
    let restored_proof = restored_handshake.remove(0);
    let responder_proof = take_outbound(call(responder.receive_frame(&three).unwrap()));
    let responder_contribution = take_outbound(call(
        responder.accept_resume_proof(&restored_proof).unwrap(),
    ));
    let restored_contribution = take_outbound(call(
        restored.accept_resume_proof(&responder_proof).unwrap(),
    ));
    let restored_result = call(restored.receive_frame(&responder_contribution).unwrap());
    let mut restored_frames = outbound_frames(restored_result);
    assert_eq!(restored_frames.len(), 1);
    let resent_pending = restored_frames.remove(0);
    let _ = responder.receive_frame(&restored_contribution).unwrap();

    let received = call(responder.receive_frame(&resent_pending).unwrap());
    assert!(has_text(&received, &pending_id, "pending across refresh"));
}

#[wasm_bindgen_test]
fn malformed_input_is_terminal() {
    let room = [0x61; 32];
    let mut session = WebSession::new(b'i', &room, None).unwrap();

    assert_code(session.receive_frame(&[0, 2, 1]), "PROTOCOL_ERROR");
    assert_code(session.start_handshake(), "SESSION_TERMINATED");
}

#[wasm_bindgen_test]
fn encrypted_burn_is_two_sided_and_terminal() {
    let (mut initiator, mut responder) = established_sessions();

    let burn_frame = take_outbound(call(initiator.burn().unwrap()));
    assert_code(initiator.send_text("after burn"), "SESSION_TERMINATED");

    let peer_result = call(responder.receive_frame(&burn_frame).unwrap());
    assert!(peer_result
        .events
        .iter()
        .any(|event| matches!(event, TestEvent::Burned)));
    assert_code(responder.send_text("after peer burn"), "SESSION_TERMINATED");
}

#[wasm_bindgen_test]
fn forged_recovery_ciphertext_is_terminal() {
    let (mut initiator, mut responder) = established_sessions();
    let one = take_outbound(call(initiator.begin_recovery(1).unwrap()));
    let _ = responder.begin_recovery(1).unwrap();
    let two = take_outbound(call(responder.receive_frame(&one).unwrap()));
    let mut initiator_frames = outbound_frames(call(initiator.receive_frame(&two).unwrap()));
    let three = initiator_frames.remove(0);
    let mut forged_proof = initiator_frames.remove(0);
    let _ = responder.receive_frame(&three).unwrap();
    let last = forged_proof.len() - 1;
    forged_proof[last] ^= 1;

    assert_code(
        responder.accept_resume_proof(&forged_proof),
        "CRYPTOGRAPHIC_FAILURE",
    );
    assert_code(responder.send_text("must stay dead"), "SESSION_TERMINATED");
}

#[wasm_bindgen_test]
fn oversized_frame_is_terminal() {
    let room = [0x81; 32];
    let mut session = WebSession::new(b'i', &room, None).unwrap();
    assert_code(session.receive_frame(&[0x10, 0x01]), "MESSAGE_TOO_LARGE");
    assert_code(session.start_handshake(), "SESSION_TERMINATED");
}

#[wasm_bindgen_test]
fn exported_session_methods_match_the_public_allowlist() {
    let session = WebSession::new(b'i', &[0x91; 32], None).unwrap();
    let value: wasm_bindgen::JsValue = session.into();
    let prototype = js_sys::Object::get_prototype_of(&value);
    let names = js_sys::Object::get_own_property_names(&prototype);
    let mut actual: Vec<String> = names.iter().filter_map(|name| name.as_string()).collect();
    actual.sort();

    let mut expected = vec![
        "__destroy_into_raw",
        "accept_resume_proof",
        "begin_recovery",
        "burn",
        "copy_worker_snapshot_for_storage",
        "confirm_user_verified",
        "constructor",
        "free",
        "receive_frame",
        "recovery_snapshot_for_worker_storage",
        "relay_handshake_confirmed",
        "send_text",
        "start_handshake",
    ];
    expected.sort_unstable();
    assert_eq!(actual, expected);
}

fn established_sessions() -> (WebSession, WebSession) {
    let room = [0x71; 32];
    let mut initiator = WebSession::new(b'i', &room, None).unwrap();
    let mut responder = WebSession::new(b'r', &room, Some(vec![0x72; 32])).unwrap();

    let one = take_outbound(call(initiator.start_handshake().unwrap()));
    let two = take_outbound(call(responder.receive_frame(&one).unwrap()));
    let three = take_outbound(call(initiator.receive_frame(&two).unwrap()));
    let _ = responder.receive_frame(&three).unwrap();
    let initiator_contribution =
        take_outbound(call(initiator.relay_handshake_confirmed().unwrap()));
    let responder_contribution =
        take_outbound(call(responder.relay_handshake_confirmed().unwrap()));
    let _ = responder.receive_frame(&initiator_contribution).unwrap();
    let _ = initiator.receive_frame(&responder_contribution).unwrap();
    let initiator_verified = take_outbound(call(initiator.confirm_user_verified().unwrap()));
    let responder_verified = take_outbound(call(responder.confirm_user_verified().unwrap()));
    let _ = responder.receive_frame(&initiator_verified).unwrap();
    let _ = initiator.receive_frame(&responder_verified).unwrap();

    (initiator, responder)
}

fn call(value: wasm_bindgen::JsValue) -> CallResult {
    serde_wasm_bindgen::from_value(value).unwrap()
}

fn take_outbound(result: CallResult) -> Vec<u8> {
    result
        .events
        .into_iter()
        .find_map(|event| match event {
            TestEvent::Outbound { frame } => Some(frame),
            _ => None,
        })
        .expect("outbound frame")
}

fn outbound_frames(result: CallResult) -> Vec<Vec<u8>> {
    result
        .events
        .into_iter()
        .filter_map(|event| match event {
            TestEvent::Outbound { frame } => Some(frame),
            _ => None,
        })
        .collect()
}

fn take_verification(result: CallResult) -> (Vec<String>, [u16; 7]) {
    result
        .events
        .into_iter()
        .find_map(|event| match event {
            TestEvent::Verification { emojis, numeric } => Some((emojis, numeric)),
            _ => None,
        })
        .expect("verification event")
}

fn has_peer_verified(result: CallResult) -> bool {
    result
        .events
        .iter()
        .any(|event| matches!(event, TestEvent::PeerVerified))
}

fn has_text(result: &CallResult, expected_id: &[u8], expected_text: &str) -> bool {
    result.events.iter().any(|event| {
        matches!(
            event,
            TestEvent::Text { id, text }
                if id == expected_id && text == expected_text
        )
    })
}

fn has_acknowledgement(result: &CallResult, expected_id: &[u8]) -> bool {
    result
        .events
        .iter()
        .any(|event| matches!(event, TestEvent::Acknowledgement { id } if id == expected_id))
}

fn assert_code(result: Result<wasm_bindgen::JsValue, wasm_bindgen::JsValue>, expected: &str) {
    #[derive(Deserialize)]
    struct PublicError {
        code: String,
    }

    let error = result.expect_err("operation should fail");
    let public: PublicError = serde_wasm_bindgen::from_value(error).unwrap();
    assert_eq!(public.code, expected);
}

fn assert_restore_code(result: Result<WebSession, wasm_bindgen::JsValue>, expected: &str) {
    #[derive(Deserialize)]
    struct PublicError {
        code: String,
    }

    let error = result.err().expect("restore should fail");
    let public: PublicError = serde_wasm_bindgen::from_value(error).unwrap();
    assert_eq!(public.code, expected);
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
