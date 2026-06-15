#!/usr/bin/env bash
# One-time setup for the scoped-token egress shim.
#   1. installs mitmproxy (isolated, via uv tool)
#   2. generates mitmproxy's CA (first run) and makes the agent trust it
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SYS_BUNDLE=/etc/ssl/certs/ca-certificates.crt
MITM_CA="$HOME/.mitmproxy/mitmproxy-ca-cert.pem"

echo "==> installing mitmproxy"
if ! command -v mitmdump >/dev/null 2>&1; then
  # uv tool keeps it off the system python; pin a py mitmproxy supports.
  uv tool install --python 3.12 mitmproxy
fi
command -v mitmdump

echo "==> generating mitmproxy CA (brief headless run)"
if [ ! -f "$MITM_CA" ]; then
  timeout 5 mitmdump --listen-host 127.0.0.1 --listen-port 18080 -q >/dev/null 2>&1 || true
fi
test -f "$MITM_CA"

echo "==> trusting the local shim CA system-wide (node/python/curl)"
# Idempotent: key off the cert's sha256 fingerprint recorded in a marker line.
FP="$(openssl x509 -in "$MITM_CA" -noout -fingerprint -sha256 | cut -d= -f2)"
if ! grep -qF "# scoped-token-shim mitmproxy CA $FP" "$SYS_BUNDLE"; then
  { echo "# scoped-token-shim mitmproxy CA $FP"; cat "$MITM_CA"; } | sudo tee -a "$SYS_BUNDLE" >/dev/null
  echo "    appended mitmproxy CA to $SYS_BUNDLE"
else
  echo "    mitmproxy CA already present"
fi

echo
echo "Setup done. Start the shim with:  $HERE/run.sh"
