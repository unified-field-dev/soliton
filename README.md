# Soliton

[![CI](https://github.com/unified-field-dev/soliton/actions/workflows/ci.yml/badge.svg)](https://github.com/unified-field-dev/soliton/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

[GitHub](https://github.com/unified-field-dev/soliton) · `cargo doc -p soliton --open`

Axum process host: resolve a listen address, bind TCP, serve a `Router`, and attach per-request extensions. Also provides `GET /health`, optional HMAC bearer middleware for subsystem HTTP APIs, and a Tokio runtime helper with a configurable worker stack. Built on Axum and Tokio.

```toml
[dependencies]
soliton = { git = "https://github.com/unified-field-dev/soliton", tag = "v0.1.0" }
anyhow = "1"
axum = "0.8"
tokio = { version = "1", features = ["rt-multi-thread", "macros", "net"] }
```

```rust
use axum::{middleware::from_fn, routing::get, Router};
use soliton::listener::{bind_tcp_with_policy, resolve_listen_addr, ListenAddrDefault};
use soliton::subsystem_auth::axum_optional_subsystem_hmac;
use soliton::{health_router, serve};

fn app() -> Router {
    Router::new()
        .route("/api/ping", get(|| async { axum::http::StatusCode::OK }))
        .merge(health_router())
        .layer(from_fn(axum_optional_subsystem_hmac))
}

fn main() -> anyhow::Result<()> {
    soliton::tokio_runtime::run(async {
        let addr = resolve_listen_addr(ListenAddrDefault::Loopback { port: 3002 })?;
        let listener = bind_tcp_with_policy(addr).await?;
        serve(listener, app()).await
    })
}
```

## About

- `resolve_listen_addr` / `ListenAddrDefault` / `ensure_bind_allowed` / `bind_tcp_with_policy` / `bind_tcp` / `serve` / `serve_with_graceful_shutdown` — listen policy and Axum accept loop
- `RequestExtensionState` + `attach_request_extensions` — per-request host state injection
- `health_router` — `GET /health`
- `subsystem_auth` — HMAC bearer for `/api` and `/__handoff_internal` (`SUBSYSTEM_AUTH_HMAC_KEY`, ≥32 bytes; fail-closed when unset/too short)
- `tokio_runtime::run` — multi-thread Tokio with configurable worker stack (`SOLITON_WORKER_STACK_BYTES`, default 8 MiB)
- Telemetry — structured `tracing` at bind/serve/HMAC-reject/stack-env boundaries; **hosts own the subscriber**

See [SECURITY.md](SECURITY.md) for host composition requirements and residual risks.

## Examples

Start here — full host wire-up: [soliton/examples/README.md](soliton/examples/README.md) (`process_host`).

## Verify

```bash
export CARGO_BUILD_JOBS=1
cargo test --workspace
```

See also [docs/VERIFICATION.md](docs/VERIFICATION.md).

## License

MIT. See [LICENSE](LICENSE), [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md), and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
