#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" -ne 1 ]]; then
  echo "Usage: $0 /path/to/certificate.pem" >&2
  exit 1
fi

CERTIFICATE_PATH="$1"

if [[ ! -r "${CERTIFICATE_PATH}" ]]; then
  echo "Certificate is not readable: ${CERTIFICATE_PATH}" >&2
  exit 1
fi

openssl x509 -in "${CERTIFICATE_PATH}" -pubkey -noout \
  | openssl pkey -pubin -outform DER \
  | openssl dgst -sha256 -binary \
  | od -An -tx1 \
  | tr -d ' \n'
printf '\n'
