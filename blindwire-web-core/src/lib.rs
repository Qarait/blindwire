//! WebAssembly feasibility exports for BlindWire's shared protocol core.
//!
//! Browser mode relies on normal user-agent TLS validation. It lacks native
//! SPKI pinning and signed-binary code-delivery assurance, so it must not be
//! treated as equivalent to a natively pinned, signed desktop client.

#![forbid(unsafe_code)]

mod session;

use blindwire_core::invite::{InvitePayload, OFFICIAL_RELAY_HOST};
use serde::Serialize;
use wasm_bindgen::prelude::*;

pub use session::WebSession;

/// Return the version of the shared core used by this WebAssembly crate.
#[wasm_bindgen]
pub fn core_version() -> String {
    env!("CARGO_PKG_VERSION").to_owned()
}

/// Generate 32 bytes of cryptographically secure browser-compatible randomness.
///
/// # Errors
///
/// Returns a JavaScript error when the operating system entropy source is unavailable.
#[wasm_bindgen]
pub fn generate_random_32() -> Result<Vec<u8>, JsValue> {
    blindwire_core::entropy::random_array::<32>()
        .map(|bytes| bytes.to_vec())
        .map_err(|_| JsValue::from_str("entropy unavailable"))
}

#[derive(Serialize)]
struct InviteDescriptor {
    room: String,
    token: String,
    expires_at: u64,
    relay_url: String,
    relay_pin: Option<String>,
    official_relay: bool,
}

#[derive(Serialize)]
struct InvitePublicError {
    code: &'static str,
    message: &'static str,
}

/// Parse and validate one invite URI for the browser Worker.
#[wasm_bindgen]
pub fn parse_invite(uri: &str) -> Result<JsValue, JsValue> {
    let payload = InvitePayload::parse_at(uri, js_sys::Date::now() as u64).map_err(|_| {
        serde_wasm_bindgen::to_value(&InvitePublicError {
            code: "INVITE_INVALID",
            message: "The invite link is invalid or expired.",
        })
        .unwrap_or_else(|_| JsValue::from_str("invite invalid"))
    })?;

    serde_wasm_bindgen::to_value(&InviteDescriptor {
        room: payload.room,
        token: payload.token,
        expires_at: payload.exp,
        relay_url: payload.relay_url.to_string(),
        relay_pin: payload.relay_pin,
        official_relay: payload.relay_url.host_str() == Some(OFFICIAL_RELAY_HOST),
    })
    .map_err(|_| JsValue::from_str("invite serialization failed"))
}
