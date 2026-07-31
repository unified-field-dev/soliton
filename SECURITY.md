# Security Policy

## Supported versions

Security fixes are accepted against the latest `main` branch and tagged releases (`0.1.x` / `0.2.x`) of this repository's crates (`soliton`).

## Reporting a vulnerability

Please **do not** open a public GitHub issue for security-sensitive reports.

Prefer one of the following:

1. **GitHub Security Advisories** — use [Report a vulnerability](https://github.com/unified-field-dev/soliton/security/advisories/new) on this repository when available.
2. Contact the maintainers privately via the repository owner listed at https://github.com/unified-field-dev/soliton.

Include:

- a description of the issue and its impact
- steps to reproduce or a proof of concept when possible
- affected crate names and versions

We will acknowledge receipt as soon as practical and coordinate a fix and disclosure timeline with you.

## Scope

In scope: vulnerabilities in this repository's published crates and documentation that could cause unsafe production defaults, plus CI/supply-chain issues in this repository.

Out of scope: vulnerabilities solely in third-party dependencies unless this project mishandles them in a security-relevant way.

## Host composition checklist

Soliton is a leaf Axum process-host kit. Security gates are composed by the host:

1. Resolve a listen address with [`resolve_listen_addr`](soliton/src/listener.rs) (prefer `ListenAddrDefault::Loopback` for embedded).
2. Call [`ensure_bind_allowed`](soliton/src/listener.rs) (or [`bind_tcp_with_policy`](soliton/src/listener.rs)) before binding non-loopback addresses — non-loopback requires `SUBSYSTEM_AUTH_HMAC_KEY` to be set.
3. For subsystem HTTP APIs under `/api` or `/__handoff_internal`, layer [`axum_optional_subsystem_hmac`](soliton/src/subsystem_auth.rs). Key presence alone does **not** attach the middleware.
4. SSR / browser-facing hosts that use session auth may omit the HMAC layer; they must still use a safe bind policy and edge TLS as appropriate.

Bare [`serve`](soliton/src/http_serve.rs) / [`bind_tcp`](soliton/src/listener.rs) do not apply HMAC or bind policy by themselves.

## Subsystem HMAC

[`axum_optional_subsystem_hmac`](soliton/src/subsystem_auth.rs) authenticates M2M requests (shared secret, not end-user sessions):

| Path | Behavior |
|------|----------|
| Exact `/health`, and paths under `/internal/` | Always pass through (probe class — see below) |
| Exact `/api`, `/api/*`, exact `/__handoff_internal`, `/__handoff_internal/*` | Enforced |
| Other paths | Pass through |

**Fail closed:** when `SUBSYSTEM_AUTH_HMAC_KEY` is missing, empty, shorter than 32 bytes, or not usable hex after `hex:`, enforced paths return **401**.

**Key material:** UTF-8 bytes or `hex:` + hex bytes; minimum **32 bytes** after decoding. Prefer a high-entropy secret (e.g. 32 random bytes as `hex:`).

**Statuses:** missing key/header → **401**; bad tag → **403**; body over 4 MiB on enforced paths → **400**.

`SUBSYSTEM_REQUIRE_AUTH_HMAC` / [`require_subsystem_hmac_from_env`](soliton/src/subsystem_auth.rs) are available for host-level checks; the middleware does **not** read that env (fail-closed is already the default when the key is missing).

HMAC covers `METHOD + "\n" + path_and_query + "\n" + body` (SHA-256). There is no timestamp/nonce in this kit — treat replay as a residual risk mitigated by private cell networks, TLS/mTLS or gateway auth, key rotation, and host authorization on mutations.

## Probe path convention (`/health` and `/internal/*`)

- This crate defines **only** [`health_router`](soliton/src/health.rs) (`GET /health` → empty `200 OK`).
- It does **not** define `/internal/*` handlers. Hosts mount readiness probes (for example database-ready checks) under `/internal/`.
- The HMAC middleware intentionally skips `/health` and `/internal/*` so load balancers and cell orchestrators can probe without M2M credentials.
- Those routes must stay readiness/liveness only (no secrets, no admin actions). Restrict who can reach subsystem ports (loopback bind, private cell ACL, mesh policy). A path prefix named `/internal` is **not** authentication.

## Residual risks (accepted for this kit)

| Topic | Expectation |
|-------|-------------|
| Probe bypass | Open by design for `/health` and host `/internal/*`; keep probes non-sensitive; limit network exposure |
| HMAC replay | No timestamp/nonce; rely on private topology, transport security, key rotation, and host authz |
| 4 MiB body buffer | Enforced paths buffer up to 4 MiB for MAC verification; add ingress body limits / rate limits at the host or edge |
| Plain HTTP | No TLS in this crate; terminate TLS or mTLS at the edge/mesh when subsystem ports leave loopback |
| Opt-in gates | Hosts must call bind policy and layer HMAC for subsystem APIs |

Do not treat “internal IP addresses only” as a complete security boundary.

## Security map (kit surfaces)

| Surface | Asset | Entry | Authn | Authz |
|---------|-------|-------|-------|-------|
| Subsystem HMAC | M2M API authenticity | `axum_optional_subsystem_hmac` | HMAC-SHA256 shared secret | None in kit — host must authorize |
| Listen / bind | Socket exposure | `resolve_listen_addr`, `ensure_bind_allowed`, `bind_tcp_with_policy` | Key **presence** for non-loopback | Not proof middleware is layered |
| Health | Liveness | `GET /health` | None | None (status-only) |
| Request extensions | Host state injection | `attach_request_extensions` | None | Not an auth boundary |
