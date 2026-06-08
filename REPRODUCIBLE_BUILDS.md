# Reproducible Builds

BlindWire artifacts are designed for bit-for-bit reproducibility. This document outlines how to build and verify binaries.

## Prerequisites

- **Rust Toolchain**: Pinned to the version in `rust-toolchain.toml` (1.88.0).
- **Environment**: Linux (Ubuntu 22.04 recommended for released binaries) or Windows (11).

## Build Process

Release builds require the official relay's SPKI-SHA256 pin set. Provide one
current pin and, during key rotation, one next pin as lowercase or uppercase
64-character hexadecimal values:

```powershell
$env:BLINDWIRE_OFFICIAL_SPKI_PINS = "<current-64-hex>[,<next-64-hex>]"
```

The pin set is public release metadata, not a secret. Record it alongside the
tag and checksums so independent rebuilders use exactly the same input. Release
compilation fails if the variable is absent, malformed, duplicated, or contains
more than two pins.

To generate a deterministic release binary:

```powershell
# Clean build artifacts
cargo clean

# Build release artifacts with deterministic profile
cargo build --release --workspace
```

The deterministic profile in the workspace `Cargo.toml` uses `codegen-units = 1` and `lto = true` to ensure consistent output.

## Verification

To verify a binary against the source:

1. Clone the repository at the target tag/commit.
2. Run the build process above.
3. Compute the SHA-256 checksum of the resulting binary.

### Example (PowerShell)
```powershell
Get-FileHash ./target/release/blindwire-server.exe -Algorithm SHA256
```

### Example (Linux)
```bash
sha256sum ./target/release/blindwire-server
```

## Release Checksums

Official releases include a `SHA256SUMS` file signed with the project's PGP key. Always verify the signature and checksum before deployment.
