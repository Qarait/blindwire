//! BlindWire Transport
//!
//! High-level async transport library for BlindWire secure messaging.
//!
//! This crate wraps `blindwire-core` and provides a simple API for establishing
//! secure sessions over the signaling server relay.
//!
//! # Security Invariants & Hard Failures
//!
//! BlindWire follows a "Hard Fail" philosophy: any error (protocol violation,
//! validation failure, or transport loss) results in **immediate session termination**.
//!
//! - **One Strike**: Any validation error in `send_text()` or `recv()` kills the session.
//! - **Fixed Limits**: The 4000-byte message limit is a hard protocol invariant to
//!   ensure frames fit within a single MTU-friendly wire package (4096 bytes).
//! - **No Duplication**: `SecureSession` and `Message` do not implement `Clone`.
//! - **Implicit Cleanup**: `Drop` defensively burns the session if it hasn't been
//!   explicitly burned via `burn()`.
//! - **Zeroization**: All plaintext and key material is zeroized using the `Zeroize`
//!   trait at the earliest possible point.
//! - **Strict Framing**: Strict 1:1 WebSocket message to Frame mapping. No buffering.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]

pub mod config;
pub mod error;
pub mod message;
mod relay;
pub mod session;

pub use config::{Role, TransportConfig};
pub use error::TransportError;
pub use message::Message;
pub use session::SecureSession;
