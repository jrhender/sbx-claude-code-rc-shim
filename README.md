# scoped-token-shim

A tiny [mitmproxy](https://mitmproxy.org/) addon that lets **Claude Code Remote Control (RC)** run fully inside a [Docker Sandbox (`sbx`)](https://docs.docker.com/ai/sandboxes/).

## The problem

Inside an sbx sandbox, all HTTPS egress goes through sbx's **forward proxy**, which
rewrites the `Authorization` header **unconditionally** to inject the real
credential (the VM only ever holds a `proxy-managed` placeholder).

That's correct for inference and for the RC calls that authenticate with the main
OAuth token (session create, credential fetch). But RC's **worker / work-lease /
transcript** planes authenticate with **per-session scoped tokens**, not the
OAuth — so the unconditional rewrite clobbers them:

```
worker → 401 · SSE stream → 403 · worker_register_failed
```

See docker/sbx-releases#8 for the upstream discussion.

## How it works

The addon runs as a local explicit HTTPS proxy in front of the agent. It **defaults
every flow to sbx's forward proxy** (injection unchanged) and only forces a request
**direct** (skipping injection) when **both** are true:

1. the path matches the scoped-token regex, **and**
2. the outgoing `Authorization` / `x-api-key` does **not** contain sbx's
   `proxy-managed` sentinel (i.e. it's already a real scoped token).

```
^/v1/(?:code/sessions/[^/]+/|environments/[^/]+/work/|sessions/[^/]+/events)
```

Direct egress still leaves the VM through sbx's **transparent** proxy, so network
policy is still enforced — only credential injection is skipped.

Two extra details that matter for a real (multiplexing) client:

- **`via` is pinned explicitly on every flow** (gateway for non-scoped, direct for
  scoped) so mitmproxy's connection pool can't reuse a direct connection for an
  injected request — otherwise inference silently leaks onto the direct path and
  401s with `Invalid bearer token`.
- **SSE responses are streamed** (`flow.response.stream = True`) so the RC inbound
  event channel (and streamed inference) isn't buffered by the proxy.
- **The server-injected "message sent" timestamp is stripped** from inbound RC
  messages (see below).

## Inbound message timestamp stripping

Messages sent from a remote client (e.g. the mobile app) arrive on the events SSE
stream prefixed, **server-side**, with a reminder line:

```
<system-reminder>Message sent at Mon 2026-06-15 03:50:14 UTC.</system-reminder>
/clear
```

Because that line lands **before** your text, a leading slash-command like `/clear`
is no longer the first thing in the message and stops being recognised. The prefix
is injected upstream (it isn't in the local Claude Code bundle), so it travels the
wire through this shim — which means the shim can remove it. With
`SHIM_STRIP_MSG_TIMESTAMP=1` (the default) the addon rewrites the inbound events
stream to drop **only** that one reminder (and its trailing newline); every other
`system-reminder` is left untouched. Set `SHIM_STRIP_MSG_TIMESTAMP=0` to keep it.

## Usage

```bash
./setup.sh                 # one-time: install mitmproxy + trust its CA
./run.sh                   # start the shim on 127.0.0.1:8080  (add SHIM_DEBUG=1 for logs)
./rc-claude.sh --debug     # launch Claude Code routed through the shim
```

Then run `/remote-control` inside Claude Code.

> `rc-claude.sh` sets **both** upper- and lower-case proxy vars. node/undici prefers
> the lowercase names, which the sandbox pre-sets to the gateway; overriding only the
> uppercase ones silently bypasses the shim.

## Configuration (env vars)

| var | default | meaning |
|---|---|---|
| `SHIM_LISTEN_HOST` / `SHIM_LISTEN_PORT` | `127.0.0.1` / `8080` | where the shim listens |
| `SBX_FORWARD_PROXY` | `http://gateway.docker.internal:3128` | sbx's injecting forward proxy |
| `SBX_PROXY_SENTINEL` | `proxy-managed` | placeholder marker that means "inject me" |
| `SHIM_SCOPED_HOST` | `api.anthropic.com` | host the bypass applies to |
| `SHIM_STRIP_MSG_TIMESTAMP` | `1` | `1` → strip the server-injected `Message sent at …` reminder from inbound RC messages; `0` → keep it |
| `SHIM_DEBUG` | unset | `1` → log routing decisions (redacted cred tail) to `shim.log` |

## Notes

- Quiet by default; no credential material is written anywhere unless `SHIM_DEBUG=1`.
- The shim becomes a hard dependency while the session is routed through it — if it
  stops, the session loses API egress. Keep `run.sh` running.
