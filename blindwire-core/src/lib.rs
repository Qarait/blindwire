//! BlindWire Protocol Core
//!
//! Minimal, dissident-grade secure messaging protocol implementation.
//!
//! This crate provides:
//! - Wire framing with strict bounds checking
//! - Protocol state machine with hard failure semantics
//! - Noise_XX handshake wrapper
//!
//! # Security Invariants & Defense-in-Depth
//!
//! - Any protocol violation terminates the session
//! - Any bounds violation terminates the session
//! - Any cryptographic failure terminates the session
//! - Direct use of `unsafe` is forbidden (#![forbid(unsafe_code)])
//! - Best-effort zeroization of key material and plaintext on session end
//! - No retries, no recovery, no partial processing

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![cfg_attr(not(test), deny(clippy::unwrap_used))]
#![cfg_attr(not(test), deny(clippy::expect_used))]
#![cfg_attr(not(test), deny(clippy::panic))]

pub mod error;
pub mod frame;
pub mod noise;
pub mod state;

pub use error::ProtocolError;
pub use frame::{Frame, MessageType};
pub use noise::NoiseSession;
pub use state::{Session, SessionState};
