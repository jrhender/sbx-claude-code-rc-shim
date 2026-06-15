"""
Scoped-token egress shim for Docker Sandboxes (sbx).

Runs as a local explicit HTTPS proxy in front of the agent. By default every
flow is forwarded to sbx's forward proxy (gateway.docker.internal:3128), so
credential injection is unchanged. A flow is forced DIRECT (skipping the
forward proxy, hence skipping injection) only when BOTH hold:

  1. the request path matches SCOPED_PATH_RE, and
  2. the outgoing Authorization / x-api-key is already a real scoped token
     -- i.e. it does NOT contain sbx's proxy-managed sentinel placeholder.

Direct flows still leave the VM through sbx's *transparent* proxy, so network
policy is still enforced. Only credential injection is skipped.

Run with --mode upstream:http://gateway.docker.internal:3128 so the DEFAULT for
every flow is the injecting forward proxy; this addon only *clears* the upstream
(via=None) for the exception flows.
"""
import os
import re
import logging

from urllib.parse import urlparse

from mitmproxy import http

# Single regex against the request path, all on api.anthropic.com.
SCOPED_PATH_RE = re.compile(
    r"^/v1/(?:code/sessions/[^/]+/|environments/[^/]+/work/|sessions/[^/]+/events)"
)

SCOPED_HOST = os.environ.get("SHIM_SCOPED_HOST", "api.anthropic.com")

# The injecting forward proxy, as a mitmproxy `via` spec ("http", (host, port)).
# We set this EXPLICITLY on every non-scoped flow (rather than relying on the
# upstream-mode default) so mitmproxy's server-connection pool keys on `via` and
# never reuses a DIRECT (via=None) connection for an injected flow, or vice versa.
_fwd = urlparse(os.environ.get("SBX_FORWARD_PROXY", "http://gateway.docker.internal:3128"))
GATEWAY_VIA = ("https" if _fwd.scheme == "https" else "http",
               (_fwd.hostname, _fwd.port or 3128))

# Substring identifying sbx's placeholder credential. The agent emits
# "sk-ant-oat01-proxy-managed" / "sk-ant-ort01-proxy-managed" on normal flows,
# and sbx's forward proxy swaps it for the real key -- so any flow carrying this
# marker MUST stay on the injecting upstream. A real scoped token won't contain
# it, so the addon routes that one direct. Override via env only if sbx changes
# the marker. (This is a public placeholder string, not a secret.)
SENTINEL = os.environ.get("SBX_PROXY_SENTINEL", "proxy-managed")

# Set SHIM_DEBUG=1 to log the routing decision (with a redacted cred tail). Use
# this to discover the sentinel value the agent actually sends.
DEBUG = os.environ.get("SHIM_DEBUG") == "1"

# Set SHIM_REVEAL_CRED=1 to log the FULL Authorization/x-api-key value. Only for
# one-off sentinel discovery in your own sandbox -- turn it back off afterwards.
REVEAL_CRED = os.environ.get("SHIM_REVEAL_CRED") == "1"

# Inbound RC messages from a remote client (e.g. the mobile app) arrive on the
# events SSE stream prefixed, server-side, with
#   <system-reminder>Message sent at <ts> UTC.</system-reminder>\n
# That text is injected upstream (it is NOT in the local Claude Code bundle), so
# it travels the wire through this shim. The leading line breaks slash-commands
# like /clear, which must be the first characters of the message. With
# SHIM_STRIP_MSG_TIMESTAMP=1 (default) the shim removes just that one reminder
# (and its trailing newline) from inbound event payloads; every other
# system-reminder is left untouched. Set =0 to keep the timestamp.
STRIP_MSG_TIMESTAMP = os.environ.get("SHIM_STRIP_MSG_TIMESTAMP", "1") != "0"

# Matches the server-injected timestamp reminder inside the JSON-encoded SSE
# payload. On the wire the trailing newline is JSON-escaped as the two bytes
# \n, so accept either that or a real newline. [^<]*? keeps the match from
# crossing into any following tag, so only this reminder is ever removed.
_MSG_TS_RE = re.compile(
    rb"<system-reminder>Message sent at [^<]*?</system-reminder>(?:\\n|\n)?"
)

logger = logging.getLogger("scoped-shim")
logger.propagate = False

# Quiet by default. With SHIM_DEBUG=1, tee routing decisions (redacted cred tail)
# to a file next to the addon so they can be inspected without the terminal.
_LOGFILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "shim.log")
if DEBUG and not any(isinstance(h, logging.FileHandler) for h in logger.handlers):
    _fh = logging.FileHandler(_LOGFILE)
    _fh.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
    logger.addHandler(_fh)
    logger.setLevel(logging.INFO)


def _creds(flow: http.HTTPFlow) -> str:
    return (
        flow.request.headers.get("authorization", "")
        or flow.request.headers.get("x-api-key", "")
    )


def _is_real_scoped_token(creds: str) -> bool:
    if not creds:
        return False
    if not SENTINEL:
        # Cannot distinguish placeholder from real token -> never bypass.
        return False
    return SENTINEL not in creds


def requestheaders(flow: http.HTTPFlow) -> None:
    if flow.request.pretty_host != SCOPED_HOST:
        return

    path = flow.request.path.split("?", 1)[0]
    creds = _creds(flow)
    matched = bool(SCOPED_PATH_RE.match(path))
    real = _is_real_scoped_token(creds)

    if matched and real:
        # Force this flow direct: no upstream forward proxy, so no injection.
        flow.server_conn.via = None
        decision = "DIRECT  (skip injection)"
    else:
        # Explicitly pin the injecting forward proxy. Setting this on EVERY
        # non-scoped flow (not just relying on the upstream-mode default) keeps
        # the connection pool from reusing a DIRECT connection here.
        flow.server_conn.via = GATEWAY_VIA
        decision = "UPSTREAM(inject)"

    if not DEBUG:
        return
    if REVEAL_CRED:
        shown = creds if creds else "<none>"
    else:
        # Show scheme + tail + whether the sentinel marker is present.
        scheme = creds.split(" ", 1)[0] if " " in creds else ""
        tail = ("…" + creds[-6:]) if creds else "<none>"
        shown = f"{scheme} {tail} sentinel_present={SENTINEL in creds if creds else False}"
    h = flow.request.headers
    diag = (
        f"http={flow.request.http_version}"
        f" beta={h.get('anthropic-beta', '-')}"
        f" xapikey={'Y' if 'x-api-key' in h else 'n'}"
    )
    logger.info(
        "%-6s %s -> %s (match=%s real_token=%s cred=[%s] %s)",
        flow.request.method, path, decision, matched, real, shown, diag,
    )


def _strip_msg_timestamp(chunk: bytes) -> bytes:
    # mitmproxy streaming modifier: called per response chunk (and once with b""
    # at end-of-stream). Removing a fully-matched reminder is safe; in the rare
    # case one is split across a chunk boundary it simply isn't stripped that
    # time (degrades to the old behaviour) rather than corrupting the stream.
    return _MSG_TS_RE.sub(b"", chunk)


def responseheaders(flow: http.HTTPFlow) -> None:
    # Stream Server-Sent-Events instead of buffering. mitmproxy otherwise waits
    # for the full response body before forwarding -- but an SSE stream (the RC
    # inbound channel, and streamed inference) never completes, so events would
    # pile up in the proxy and never reach the client. Setting stream flushes
    # chunks through as they arrive; assigning a function rewrites each chunk.
    if flow.request.pretty_host != SCOPED_HOST:
        return
    ct = flow.response.headers.get("content-type", "")
    path = flow.request.path.split("?", 1)[0]
    if not ("text/event-stream" in ct or path.endswith("/events/stream")):
        return
    # Only rewrite the inbound RC events channel; leave inference SSE untouched.
    if STRIP_MSG_TIMESTAMP and "/events" in path:
        flow.response.stream = _strip_msg_timestamp
        mode = "STREAM+strip-ts"
    else:
        flow.response.stream = True
        mode = "STREAM"
    if DEBUG:
        logger.info("%s %s (content-type=%s)", mode, path, ct or "-")
