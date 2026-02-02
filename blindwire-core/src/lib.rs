//! BlindWire Protocol Core
//!
//! Minimal, dissident-grade secure messaging protocol implementation.
//!
//! This crate provides:
//! - Wire framing with strict bounds checking
//! - Protocol state machine with hard failure semantics
//! - Noise_XX handshake wrapper
//!
//! # Security Invariants
//!
//! - Any protocol violation terminates the session
//! - Any bounds violation terminates the session
//! - Any cryptographic failure terminates the session
//! - Keys are zeroized on session end
//! - No retries, no recovery, no partial processing

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]

pub mod error;
pub mod frame;
pub mod noise;
pub mod state;

pub use error::ProtocolError;
pub use frame::{Frame, MessageType};
pub use noise::NoiseSession;
pub use state::{Session, SessionState};
