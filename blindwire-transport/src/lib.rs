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
//! - **Fixed Limits**: The 4000-byte message limit is a hard protocol invariant.
//! - **No Duplication**: `SecureSession` and `Message` do not implement `Clone`.
//! - **Safe Surface**: No direct `unsafe` code (#![forbid(unsafe_code)]).
//! - **Implicit Cleanup**: `Drop` defensively burns the session if it hasn't been burned.
//! - **Zeroization**: Best-effort zeroization of plaintext and keys via the `Zeroize` trait.
//! - **Strict Framing**: Strict 1:1 WebSocket message to Frame mapping.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]

pub mod config;
pub mod error;
pub mod message;
mod pinning;
mod relay;
mod relay_v4;
pub mod session;
mod session_v21;

pub use config::{Role, TransportConfig};
pub use error::TransportError;
pub use message::Message;
pub use pinning::{reset_server_pin, PinResetError};
pub use session::SecureSession;
pub use session_v21::{RecoverySnapshotV21, SecureSessionV21, SessionEventV21};
