//! Full Soliton process host wire-up (copy-paste starting point).
//!
//! ## When to use
//! Bootstrap a host binary: `tokio_runtime::run`, listen policy, bind/serve,
//! health, HMAC subsystem auth, and per-request extensions.
//!
//! ## Command
//! ```bash
//! SUBSYSTEM_AUTH_HMAC_KEY='soliton-test-hmac-key-32-bytes!!' CARGO_BUILD_JOBS=1 \
//!   cargo run -p soliton --example process_host
//! ```
//!
//! Default: binds loopback (ephemeral port), serves briefly, verifies `/health` +
//! signed `/api/ping` over TCP, then graceful-shutdown exits.
//!
//! Keep listening until Ctrl-C:
//! ```bash
//! SOLITON_LISTEN=1 SUBSYSTEM_AUTH_HMAC_KEY='soliton-test-hmac-key-32-bytes!!' CARGO_BUILD_JOBS=1 \
//!   cargo run -p soliton --example process_host
//! ```
//!
//! ## Success
//! Stdout prints `process_host: OK — listen/serve, health, HMAC, extensions wired`
//! (default), or a listening URL when `SOLITON_LISTEN=1`.
//!
//! ## Look next
//! `hmac_health_host` for auth-only contract smoke; module rustdoc for each surface.

#![allow(clippy::print_stdout, clippy::unwrap_used, clippy::expect_used)]

use std::time::Duration;

use axum::extract::Extension;
use axum::http::Extensions;
use axum::middleware::{from_fn, from_fn_with_state};
use axum::routing::get;
use axum::Router;
use soliton::listener::{bind_tcp_with_policy, resolve_listen_addr, ListenAddrDefault};
use soliton::middleware::{attach_request_extensions, RequestExtensionState};
use soliton::subsystem_auth::{
    axum_optional_subsystem_hmac, load_hmac_key_material_from_env, subsystem_hmac_header_pair,
    SUBSYSTEM_AUTH_HEADER_NAME,
};
use soliton::{health_router, serve_with_graceful_shutdown};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::oneshot;

#[derive(Clone)]
struct AppState {
    label: String,
}

impl RequestExtensionState for AppState {
    fn inject_request_extensions(&self, extensions: &mut Extensions) {
        extensions.insert(self.label.clone());
    }
}

fn app(state: AppState) -> Router {
    Router::new()
        .route(
            "/api/ping",
            get(|Extension(label): Extension<String>| async move {
                (axum::http::StatusCode::OK, label)
            }),
        )
        .merge(health_router())
        .layer(from_fn(axum_optional_subsystem_hmac))
        .layer(from_fn_with_state(
            state,
            attach_request_extensions::<AppState>,
        ))
}

async fn http_exchange(addr: std::net::SocketAddr, request: &str) -> anyhow::Result<String> {
    let mut stream = tokio::net::TcpStream::connect(addr).await?;
    stream.write_all(request.as_bytes()).await?;
    let mut buf = vec![0u8; 1024];
    let n = stream.read(&mut buf).await?;
    Ok(std::str::from_utf8(&buf[..n])?.to_string())
}

async fn verify_live(addr: std::net::SocketAddr) -> anyhow::Result<()> {
    tokio::time::sleep(Duration::from_millis(20)).await;

    let health = http_exchange(
        addr,
        "GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )
    .await?;
    anyhow::ensure!(
        health.starts_with("HTTP/1.1 200"),
        "health must be open, got: {health}"
    );

    let denied = http_exchange(
        addr,
        "GET /api/ping HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )
    .await?;
    anyhow::ensure!(
        denied.starts_with("HTTP/1.1 401") || denied.starts_with("HTTP/1.1 403"),
        "unsigned /api must fail closed, got: {denied}"
    );

    let (hdr, tag) = subsystem_hmac_header_pair("GET", "/api/ping", b"")
        .ok_or_else(|| anyhow::anyhow!("SUBSYSTEM_AUTH_HMAC_KEY required (≥32 bytes)"))?;
    anyhow::ensure!(hdr == SUBSYSTEM_AUTH_HEADER_NAME);
    let signed = http_exchange(
        addr,
        &format!(
            "GET /api/ping HTTP/1.1\r\nHost: localhost\r\n{hdr}: {tag}\r\nConnection: close\r\n\r\n"
        ),
    )
    .await?;
    anyhow::ensure!(
        signed.starts_with("HTTP/1.1 200"),
        "signed /api/ping must succeed, got: {signed}"
    );
    anyhow::ensure!(
        signed.contains("soliton-demo"),
        "extension inject must reach handler, got: {signed}"
    );
    Ok(())
}

async fn run_host() -> anyhow::Result<()> {
    if load_hmac_key_material_from_env().is_none() {
        anyhow::bail!(
            "SUBSYSTEM_AUTH_HMAC_KEY must be set to at least 32 bytes \
             (example: soliton-test-hmac-key-32-bytes!!)"
        );
    }

    let keep_listening = std::env::var_os("SOLITON_LISTEN").is_some();
    let port = if keep_listening { 3002 } else { 0 };
    let addr = resolve_listen_addr(ListenAddrDefault::Loopback { port })?;
    let listener = bind_tcp_with_policy(addr).await?;
    let local = listener.local_addr()?;
    let state = AppState {
        label: "soliton-demo".to_string(),
    };
    let router = app(state);

    if keep_listening {
        println!("process_host listening on http://{local} (Ctrl-C to stop)");
        return serve_with_graceful_shutdown(listener, router, async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await;
    }

    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let serve_task = tokio::spawn(async move {
        serve_with_graceful_shutdown(listener, router, async {
            let _ = shutdown_rx.await;
        })
        .await
    });

    let verify_result = verify_live(local).await;
    let _ = shutdown_tx.send(());
    let serve_result = tokio::time::timeout(Duration::from_secs(2), serve_task)
        .await
        .map_err(|_| anyhow::anyhow!("serve join timed out"))?
        .map_err(|e| anyhow::anyhow!("serve task join: {e}"))?;
    serve_result?;
    verify_result?;

    println!("process_host: OK — listen/serve, health, HMAC, extensions wired");
    Ok(())
}

fn main() -> anyhow::Result<()> {
    soliton::tokio_runtime::run(run_host())
}
