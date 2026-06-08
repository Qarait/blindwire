# Official Relay Deployment

This directory deploys `blindwire-server` behind Nginx at
`wss://relay.blindwire.io`.

## Target

- Ubuntu 24.04 LTS VPS
- At least 1 vCPU, 1 GB RAM, and a public IPv4 address
- Cloud firewall allowing TCP 22, 80, and 443
- `relay.blindwire.io` A record pointing to the VPS
- Optional AAAA record only when IPv6 is configured and reachable

The relay process binds only to `127.0.0.1:8080`. Nginx terminates TLS and
proxies WebSocket connections. Nginx access logs are disabled and forwarded
client IP headers are blanked. The hosting provider can still observe network
metadata.

## Build

Build the relay from the reviewed release commit:

```bash
cargo build --locked --release -p blindwire-server
```

Copy the repository and `target/release/blindwire-server` to the VPS. Then run:

```bash
sudo deploy/scripts/install-relay.sh \
  target/release/blindwire-server \
  security@example.com
```

The installer:

1. Refuses to continue until `relay.blindwire.io` resolves.
2. Creates an unprivileged `blindwire` service account.
3. Installs a hardened systemd service bound to localhost.
4. Installs Nginx and Certbot.
5. Issues an ECDSA P-256 certificate with `--reuse-key`.
6. Installs the WebSocket reverse proxy and renewal reload hook.
7. Prints the certificate's SPKI-SHA256 pin.

Certbot does not reuse certificate private keys by default. BlindWire requires
`--reuse-key` because changing the official relay key without first shipping a
rotation pin causes clients to reject the relay.

## Verify

```bash
systemctl status blindwire-relay --no-pager
nginx -t
curl --fail --silent --show-error --https-only \
  https://relay.blindwire.io/healthz
sudo certbot renew --dry-run
```

Print the deployed SPKI pin:

```bash
sudo deploy/scripts/print-spki-pin.sh \
  /etc/letsencrypt/live/relay.blindwire.io/cert.pem
```

Use the current pin and a separately generated rotation pin when building
official clients:

```bash
export BLINDWIRE_OFFICIAL_SPKI_PINS="<current-pin>,<next-pin>"
```

## Operational Rules

- Never expose port 8080 publicly.
- Never enable Nginx access logs for the relay virtual host.
- Keep `RUST_LOG=warn` or stricter in production.
- Do not install analytics, request tracing, or session recording.
- Apply OS security updates promptly.
- Back up the TLS private key securely; do not commit it.
- Test key rotation before replacing the current TLS private key.
- Treat VPS compromise as metadata compromise even though message plaintext
  remains end-to-end encrypted.

## Sources

- Certbot `--reuse-key`:
  https://eff-certbot.readthedocs.io/en/stable/using.html
- Nginx WebSocket proxying:
  https://nginx.org/en/docs/http/websocket.html
