#!/usr/bin/env bash
set -euo pipefail

DOMAIN="relay.blindwire.tech"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
DEPLOY_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd)"

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run this script as root." >&2
  exit 1
fi

if [[ "$#" -ne 2 ]]; then
  echo "Usage: $0 /path/to/blindwire-server admin@example.com" >&2
  exit 1
fi

BINARY_PATH="$1"
ACME_EMAIL="$2"

if [[ ! -x "${BINARY_PATH}" ]]; then
  echo "Relay binary is missing or not executable: ${BINARY_PATH}" >&2
  exit 1
fi

if ! getent ahosts "${DOMAIN}" >/dev/null; then
  echo "${DOMAIN} does not resolve. Create its DNS record before installation." >&2
  exit 1
fi

apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y nginx certbot openssl ca-certificates

if ! getent group blindwire >/dev/null; then
  groupadd --system blindwire
fi
if ! id blindwire >/dev/null 2>&1; then
  useradd \
    --system \
    --gid blindwire \
    --home-dir /var/lib/blindwire \
    --create-home \
    --shell /usr/sbin/nologin \
    blindwire
fi

install -d -o root -g root -m 0755 /usr/local/lib/blindwire
install -o root -g root -m 0755 "${BINARY_PATH}" /usr/local/lib/blindwire/blindwire-server
install -d -o blindwire -g blindwire -m 0700 /var/lib/blindwire
install -o root -g root -m 0644 \
  "${DEPLOY_DIR}/systemd/blindwire-relay.service" \
  /etc/systemd/system/blindwire-relay.service

systemctl daemon-reload
systemctl enable --now blindwire-relay.service
systemctl is-active --quiet blindwire-relay.service

install -d -o www-data -g www-data -m 0755 /var/www/certbot
rm -f /etc/nginx/sites-enabled/default

cat >"/etc/nginx/sites-available/${DOMAIN}" <<EOF
server {
    listen 80;
    listen [::]:80;
    server_name ${DOMAIN};
    access_log off;
    server_tokens off;

    location ^~ /.well-known/acme-challenge/ {
        root /var/www/certbot;
        default_type text/plain;
    }

    location / {
        return 404;
    }
}
EOF

ln -sfn "/etc/nginx/sites-available/${DOMAIN}" "/etc/nginx/sites-enabled/${DOMAIN}"
nginx -t
systemctl enable --now nginx
systemctl reload nginx

certbot certonly \
  --webroot \
  --webroot-path /var/www/certbot \
  --domain "${DOMAIN}" \
  --cert-name "${DOMAIN}" \
  --key-type ecdsa \
  --elliptic-curve secp256r1 \
  --reuse-key \
  --non-interactive \
  --agree-tos \
  --email "${ACME_EMAIL}"

install -o root -g root -m 0644 \
  "${DEPLOY_DIR}/nginx/relay.blindwire.tech.conf" \
  "/etc/nginx/sites-available/${DOMAIN}"

install -d -o root -g root -m 0755 /etc/letsencrypt/renewal-hooks/deploy
cat >/etc/letsencrypt/renewal-hooks/deploy/reload-nginx <<'EOF'
#!/usr/bin/env sh
set -eu
systemctl reload nginx
EOF
chmod 0755 /etc/letsencrypt/renewal-hooks/deploy/reload-nginx

nginx -t
systemctl reload nginx

echo
echo "Relay installation completed."
echo "SPKI-SHA256:"
"${SCRIPT_DIR}/print-spki-pin.sh" "/etc/letsencrypt/live/${DOMAIN}/cert.pem"
