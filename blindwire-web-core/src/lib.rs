//! WebAssembly feasibility exports for BlindWire's shared protocol core.
//!
//! Browser mode relies on normal user-agent TLS validation. It lacks native
//! SPKI pinning and signed-binary code-delivery assurance, so it must not be
//! treated as equivalent to a natively pinned, signed desktop client.

#![forbid(unsafe_code)]

mod session;

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
