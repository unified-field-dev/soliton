//! Axum process host: bind a TCP listener, serve a [`Router`](axum::Router), and attach
//! per-request extensions.
//!
//! Also includes a `GET /health` router, optional HMAC bearer middleware for subsystem HTTP
//! APIs, and a multi-thread Tokio runtime helper with a configurable worker stack.
//!
//! Built on Axum and Tokio. Hosts inject their own app state (for example via
//! [`middleware::RequestExtensionState`]) and compose domain routers on the shared
//! listen/serve path.
//!
//! Operational events use the [`tracing`] crate (bind, serve lifecycle, HMAC rejects,
//! worker-stack env warnings). **Hosts own the subscriber** — without one, events are
//! no-ops.
//!
//! ## Capabilities
//!
//! - **HTTP:** [`serve`] / [`serve_with_graceful_shutdown`] bind Axum with optional graceful shutdown.
//! - **Listen policy:** [`resolve_listen_addr`], [`ensure_bind_allowed`], [`bind_tcp_with_policy`], [`bind_tcp`].
//! - **Request context:** [`middleware::attach_request_extensions`] injects host-owned extensions per request.
//! - **Runtime:** [`tokio_runtime::run`] builds a multi-thread Tokio runtime with configurable worker stack size.
//! - **Ops:** [`health`], optional [`subsystem_auth`] HMAC middleware.
//!
//! # Organized by task
//!
//! | Task | Start here |
//! |------|------------|
//! | Bind + serve Axum | [`resolve_listen_addr`], [`ensure_bind_allowed`] / [`bind_tcp_with_policy`], [`serve`] — [example](#quick-example) |
//! | Per-request host state | [`middleware::RequestExtensionState`], [`middleware::attach_request_extensions`] |
//! | Liveness endpoint | [`health_router`] (`GET /health`) |
//! | HMAC bearer auth for subsystem HTTP APIs | [`subsystem_auth`] |
//! | Deep async-stack Tokio runtime | [`tokio_runtime::run`] |
//!
//! Runnable host wire-up: `cargo run -p soliton --example process_host`
//!
//! Auth contract smoke: `cargo run -p soliton --example hmac_health_host`
//!
//! # Quick example
//!
//! ```rust,no_run
//! use axum::{middleware::from_fn, routing::get, Router};
//! use soliton::listener::{bind_tcp_with_policy, resolve_listen_addr, ListenAddrDefault};
//! use soliton::subsystem_auth::axum_optional_subsystem_hmac;
//! use soliton::{health_router, serve};
//!
//! fn app() -> Router {
//!     Router::new()
//!         .route("/api/ping", get(|| async { axum::http::StatusCode::OK }))
//!         .merge(health_router())
//!         .layer(from_fn(axum_optional_subsystem_hmac))
//! }
//!
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     soliton::tokio_runtime::run(async {
//!         let addr = resolve_listen_addr(ListenAddrDefault::Loopback { port: 3002 })?;
//!         let listener = bind_tcp_with_policy(addr).await?;
//!         serve(listener, app()).await?;
//!         Ok::<(), Box<dyn std::error::Error>>(())
//!     })
//! }
//! ```
//!
//! # Further reading
//!
//! - Crate README — dependency snippet and About inventory
//! - `DESIGN.md` — surface map for maintainers
//! - `docs/VERIFICATION.md` — test map and doc gates
//! - `SECURITY.md` — host composition and subsystem HMAC requirements

/// Typed listen and bind-policy errors.
pub mod error;
/// `GET /health` router (see [`health_router`]).
pub mod health;
mod http_serve;
/// TCP listener + bind-address resolution helpers.
pub mod listener;
/// Per-request state injection middleware (see [`middleware::RequestExtensionState`]).
pub mod middleware;
/// Optional HMAC bearer middleware for headless subsystem HTTP APIs.
pub mod subsystem_auth;
/// Multi-thread Tokio runtime helper with a configurable per-worker stack.
pub mod tokio_runtime;

pub use error::{BindPolicyError, ListenAddrError};
pub use health::health_router;
pub use http_serve::{serve, serve_with_graceful_shutdown};
pub use listener::{
    bind_tcp, bind_tcp_with_policy, ensure_bind_allowed, resolve_listen_addr, ListenAddrDefault,
};
