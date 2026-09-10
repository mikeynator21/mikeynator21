#!/usr/bin/env bash
# Convenience wrapper: check prerequisites, then run the integration testbed.
set -euo pipefail

[[ $EUID -eq 0 ]] || { echo "needs root: sudo $0" >&2; exit 1; }

missing=()
for tool in ip nft dig openssl; do
    command -v "$tool" >/dev/null || missing+=("$tool")
done
if [[ ${#missing[@]} -gt 0 ]]; then
    echo "missing: ${missing[*]}" >&2
    echo "on Debian/Ubuntu: apt install iproute2 nftables dnsutils openssl" >&2
    exit 1
fi

CERT_DIR=/tmp/wgt-certs
mkdir -p "$CERT_DIR"
if [[ ! -f "$CERT_DIR/cert.pem" ]]; then
    openssl req -x509 -newkey rsa:2048 -keyout "$CERT_DIR/key.pem" -out "$CERT_DIR/cert.pem" \
        -days 2 -nodes -subj "/CN=testbed-resolver" \
        -addext "subjectAltName=IP:10.200.0.2" >/dev/null 2>&1
fi

exec python3 "$(dirname "$0")/run_testbed.py" "$@"
