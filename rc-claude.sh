#!/usr/bin/env bash
# Launch Claude Code routed through the scoped-token shim.
#
# Must set BOTH upper- and lower-case proxy vars: node/undici prefers the
# lowercase names, and the sandbox pre-sets those to the gateway forward proxy.
# If only the uppercase ones are overridden, traffic bypasses the shim and the
# CCR worker token gets clobbered by credential injection (401/403).
set -euo pipefail

SHIM="${SHIM:-http://127.0.0.1:8080}"

# Refuse to launch if the shim isn't actually listening -- otherwise the session
# would have no API egress at all.
if ! curl -s -o /dev/null --max-time 3 "$SHIM"; then
  echo "ERROR: shim not reachable at $SHIM -- start ~/scoped-token-shim/run.sh first" >&2
  exit 1
fi

export HTTPS_PROXY="$SHIM" HTTP_PROXY="$SHIM"
export https_proxy="$SHIM" http_proxy="$SHIM"

exec claude "$@"
