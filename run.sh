#!/usr/bin/env bash
# Start the scoped-token egress shim.
#
# Default for EVERY flow = sbx's forward proxy (credential injection unchanged).
# The addon only forces the scoped paths direct when a real scoped token is
# present. Direct egress still goes through sbx's transparent proxy.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

LISTEN_HOST="${SHIM_LISTEN_HOST:-127.0.0.1}"
LISTEN_PORT="${SHIM_LISTEN_PORT:-8080}"
SBX_FORWARD_PROXY="${SBX_FORWARD_PROXY:-http://gateway.docker.internal:3128}"
SYS_BUNDLE=/etc/ssl/certs/ca-certificates.crt

exec mitmdump \
  --mode "upstream:${SBX_FORWARD_PROXY}" \
  --listen-host "$LISTEN_HOST" --listen-port "$LISTEN_PORT" \
  --set connection_strategy=lazy \
  --set ssl_verify_upstream_trusted_ca="$SYS_BUNDLE" \
  --set upstream_cert=true \
  -s "$HERE/addon.py"
