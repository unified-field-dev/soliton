# Soliton — design

Soliton owns the Axum process-host surface: resolve a listen address (strict env policy), bind TCP, and serve a `Router` (with optional graceful shutdown). Hosts compose their own routes and state on top of that path.

**Host-owned above Soliton:** Valence/DB bootstrap, sessions, Leptos/Higgs composition, and host capacity probing (Parton owns ProbeHost / `parton::host_info`).

## Listen / serve

- [`ListenAddrDefault`](soliton/src/listener.rs) / [`resolve_listen_addr`](soliton/src/listener.rs) — `LEPTOS_SITE_ADDR` → `SITE_ADDR` → default; errors on invalid env (no value echo)
- [`ensure_bind_allowed`](soliton/src/listener.rs) — non-loopback requires usable `SUBSYSTEM_AUTH_HMAC_KEY` (≥32 bytes)
- [`bind_tcp_with_policy`](soliton/src/listener.rs) — `ensure_bind_allowed` then bind (preferred for subsystem hosts)
- [`bind_tcp`](soliton/src/listener.rs) / [`serve`](soliton/src/http_serve.rs) / [`serve_with_graceful_shutdown`](soliton/src/http_serve.rs) — Axum accept loop (bind without policy when the host already gated)

Typed errors: [`ListenAddrError`](soliton/src/error.rs), [`BindPolicyError`](soliton/src/error.rs).

## Request extensions

Hosts implement [`RequestExtensionState`](soliton/src/middleware/request_context.rs) and layer [`attach_request_extensions`](soliton/src/middleware/request_context.rs) so per-request handles are injected before handlers run.

## Ops helpers

[`health_router`](soliton/src/health.rs) (`Router<S>` so hosts can merge into stateful Axum routers), [`subsystem_auth`](soliton/src/subsystem_auth.rs) HMAC middleware, and [`tokio_runtime::run`](soliton/src/tokio_runtime.rs).

## Telemetry

Soliton emits structured [`tracing`](https://docs.rs/tracing) events at bind/serve boundaries, HMAC reject (status + path class + reason; never key/body), and invalid `SOLITON_WORKER_STACK_BYTES`. **Hosts install the subscriber.** Library code never uses `println!` / `eprintln!`.

## Workspace dependency inventory

Root [`Cargo.toml`](Cargo.toml) may list shared versions (`chrono`, `serde`, `sysinfo`, …) for kit uniformity even when this member does not depend on them. Member deps live in [`soliton/Cargo.toml`](soliton/Cargo.toml); `tower` is a **dev-dependency** (test/example `ServiceExt` only).
