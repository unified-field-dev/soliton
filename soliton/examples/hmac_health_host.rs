//! HMAC-protected process host with `/health` and `/api/*`.
//!
//! ## When to use
//! Smoke for Soliton’s health router + subsystem HMAC middleware.
//!
//! ## Command
//! ```bash
//! SUBSYSTEM_AUTH_HMAC_KEY='soliton-test-hmac-key-32-bytes!!' CARGO_BUILD_JOBS=1 \
//!   cargo run -p soliton --example hmac_health_host
//! ```
//!
//! ## Success
//! Stdout prints `hmac_health_host: OK — /health open, /api HMAC enforced`.
//!
//! ## Look next
//! `process_host` for full host wire-up; `soliton::subsystem_auth` rustdoc.

#![allow(clippy::print_stdout, clippy::unwrap_used, clippy::expect_used)]

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::middleware::from_fn;
use axum::routing::get;
use axum::Router;
use soliton::listener::{bind_tcp_with_policy, resolve_listen_addr, ListenAddrDefault};
use soliton::subsystem_auth::{
    axum_optional_subsystem_hmac, load_hmac_key_material_from_env, subsystem_hmac_header_pair,
    SUBSYSTEM_AUTH_HEADER_NAME,
};
use soliton::{health_router, serve};
use tower::ServiceExt;

fn app() -> Router {
    Router::new()
        .route("/api/ping", get(|| async { StatusCode::OK }))
        .merge(health_router())
        .layer(from_fn(axum_optional_subsystem_hmac))
}

async fn self_check(router: Router) -> anyhow::Result<()> {
    let health = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .expect("health req"),
        )
        .await?;
    anyhow::ensure!(health.status() == StatusCode::OK, "health must be open");

    let denied = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/ping")
                .body(Body::empty())
                .expect("api req"),
        )
        .await?;
    anyhow::ensure!(
        denied.status() == StatusCode::UNAUTHORIZED || denied.status() == StatusCode::FORBIDDEN,
        "api without HMAC must fail closed, got {}",
        denied.status()
    );

    let (hdr, tag) = subsystem_hmac_header_pair("GET", "/api/ping", b"")
        .ok_or_else(|| anyhow::anyhow!("SUBSYSTEM_AUTH_HMAC_KEY required (≥32 bytes)"))?;
    let allowed = router
        .oneshot(
            Request::builder()
                .uri("/api/ping")
                .header(hdr, tag)
                .body(Body::empty())
                .expect("signed api req"),
        )
        .await?;
    anyhow::ensure!(
        allowed.status() == StatusCode::OK,
        "signed /api/ping must succeed"
    );
    assert_eq!(hdr, SUBSYSTEM_AUTH_HEADER_NAME);
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    if load_hmac_key_material_from_env().is_none() {
        anyhow::bail!(
            "SUBSYSTEM_AUTH_HMAC_KEY must be set to at least 32 bytes \
             (example: soliton-test-hmac-key-32-bytes!!)"
        );
    }

    self_check(app()).await?;

    // Optional listen mode: SOLITON_LISTEN=1 keeps the process host up.
    if std::env::var_os("SOLITON_LISTEN").is_some() {
        let addr = resolve_listen_addr(ListenAddrDefault::Loopback { port: 3000 })?;
        let listener = bind_tcp_with_policy(addr).await?;
        println!("hmac_health_host listening on http://{addr} (Ctrl-C to stop)");
        return serve(listener, app()).await;
    }

    println!("hmac_health_host: OK — /health open, /api HMAC enforced");
    Ok(())
}
