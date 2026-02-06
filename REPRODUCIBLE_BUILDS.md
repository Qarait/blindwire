# Reproducible Builds

BlindWire artifacts are designed for bit-for-bit reproducibility. This document outlines how to build and verify binaries.

## Prerequisites

- **Rust Toolchain**: Pinned to the version in `rust-toolchain.toml` (1.83.0).
- **Environment**: Linux (Ubuntu 22.04 recommended for released binaries) or Windows (11).

## Build Process

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
