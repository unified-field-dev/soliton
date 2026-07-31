# soliton examples

Start here for a copy-paste process host, then use the HMAC smoke when you only need auth contracts.

`SUBSYSTEM_AUTH_HMAC_KEY` must be at least **32 bytes**. The examples do not invent a key for you.

## `process_host` — full wire-up (start here)

Resolves a listen address, applies bind policy (`bind_tcp_with_policy`), serves with graceful
shutdown, merges `GET /health`, layers subsystem HMAC, injects per-request extensions, and
drives the async host via `tokio_runtime::run`.

```bash
SUBSYSTEM_AUTH_HMAC_KEY='soliton-test-hmac-key-32-bytes!!' CARGO_BUILD_JOBS=1 \
  cargo run -p soliton --example process_host
```

Success: stdout prints `process_host: OK — listen/serve, health, HMAC, extensions wired`
(binds an ephemeral loopback port, verifies over TCP, then exits).

Keep the process up:

```bash
SOLITON_LISTEN=1 SUBSYSTEM_AUTH_HMAC_KEY='soliton-test-hmac-key-32-bytes!!' CARGO_BUILD_JOBS=1 \
  cargo run -p soliton --example process_host
```

## `hmac_health_host` — HMAC contract smoke

In-process oneshot checks: `/health` open, unsigned `/api/*` fail closed, signed `/api`
succeeds. Does not listen unless `SOLITON_LISTEN=1`.

```bash
SUBSYSTEM_AUTH_HMAC_KEY='soliton-test-hmac-key-32-bytes!!' CARGO_BUILD_JOBS=1 \
  cargo run -p soliton --example hmac_health_host
```

Success: stdout prints `hmac_health_host: OK — /health open, /api HMAC enforced`.
