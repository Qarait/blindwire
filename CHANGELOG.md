# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2026-02-06

### Changed
- **BREAKING**: Protocol v2.0 introduces a versioned JOIN packet (`0x02` literal). Not compatible with v1.x.

### Added
- TLS certificate pinning with TOFU-and-Lock model.
- Per-IP rate limiting (5 connections, 10 bursts/min) and global connection cap (1000).
- QR-based session sharing via `blindwire://` URI scheme.
- ANSI/Unicode sanitization for terminal UI security.
- Explicit wire format documentation separating signaling and cryptographic layers.

### Security
- Acknowledged unauthenticated `TERMINATE` as a known DoS vector (to be addressed in v2.1).
- Refined zeroization claims to "best-effort" for accuracy.

---

## [1.1.1] - 2026-02-05

### Added
- GitHub Actions CI workflow for workspace-wide testing, linting, and security auditing.
- `rust-toolchain.toml` to pin build environment to Rust 1.83.0.
- `REPRODUCIBLE_BUILDS.md` documentation.
- Deterministic release build profile with `codegen-units = 1` and `LTO`.

### Fixed
- Signaling server frame wrapping bug: incorrectly included 2-byte length prefix in RELAY packets.
- Missing `on_connected()` state transition in integration tests causing handshake failures.
- Various Clippy lints (unused imports, unwrap usage in tests, manual range checks).
- Inconsistent frame parsing in CLI.

### Removed
- Redundant and outdated `blindwire-server/tests/signal_tests.rs`.

## [1.1.0] - 2024-01-01
- Baseline v1.1 signaling protocol.
- Ephemeral session state machine.
- Noise_XX handshake integration.
