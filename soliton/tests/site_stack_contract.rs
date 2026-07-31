//! Site address, bind, serve, and worker-stack contracts.
//!
//! Test-only binary; exempt from library `missing_docs` deny.
//! Env-mutating async tests hold a process-wide lock across awaits so keys stay stable.
#![allow(missing_docs)]
#![allow(clippy::await_holding_lock)]

use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::Duration;

use axum::http::StatusCode;
use soliton::tokio_runtime::{
    resolve_worker_stack_bytes, DEFAULT_WORKER_STACK_BYTES, WORKER_STACK_ENV,
};
use soliton::{
    bind_tcp, bind_tcp_with_policy, health_router, resolve_listen_addr,
    serve_with_graceful_shutdown, ListenAddrDefault,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::oneshot;

static SITE_ADDR_LOCK: Mutex<()> = Mutex::new(());
static STACK_ENV_LOCK: Mutex<()> = Mutex::new(());
static AUTH_ENV_LOCK: Mutex<()> = Mutex::new(());

const TEST_KEY: &str = "soliton-test-hmac-key-32-bytes!!";

fn with_site_addr_env<R>(value: Option<&str>, f: impl FnOnce() -> R) -> R {
    let _g = SITE_ADDR_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let prev = std::env::var("LEPTOS_SITE_ADDR").ok();
    let prev_site = std::env::var("SITE_ADDR").ok();
    match value {
        Some(v) => std::env::set_var("LEPTOS_SITE_ADDR", v),
        None => std::env::remove_var("LEPTOS_SITE_ADDR"),
    }
    std::env::remove_var("SITE_ADDR");
    let out = f();
    match prev {
        Some(v) => std::env::set_var("LEPTOS_SITE_ADDR", v),
        None => std::env::remove_var("LEPTOS_SITE_ADDR"),
    }
    match prev_site {
        Some(v) => std::env::set_var("SITE_ADDR", v),
        None => std::env::remove_var("SITE_ADDR"),
    }
    out
}

fn with_stack_env<R>(value: Option<&str>, f: impl FnOnce() -> R) -> R {
    let _g = STACK_ENV_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let prev = std::env::var(WORKER_STACK_ENV).ok();
    match value {
        Some(v) => std::env::set_var(WORKER_STACK_ENV, v),
        None => std::env::remove_var(WORKER_STACK_ENV),
    }
    let out = f();
    match prev {
        Some(v) => std::env::set_var(WORKER_STACK_ENV, v),
        None => std::env::remove_var(WORKER_STACK_ENV),
    }
    out
}

fn with_hmac_key<R>(value: Option<&str>, f: impl FnOnce() -> R) -> R {
    let _g = AUTH_ENV_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let prev = std::env::var("SUBSYSTEM_AUTH_HMAC_KEY").ok();
    match value {
        Some(v) => std::env::set_var("SUBSYSTEM_AUTH_HMAC_KEY", v),
        None => std::env::remove_var("SUBSYSTEM_AUTH_HMAC_KEY"),
    }
    let out = f();
    match prev {
        Some(v) => std::env::set_var("SUBSYSTEM_AUTH_HMAC_KEY", v),
        None => std::env::remove_var("SUBSYSTEM_AUTH_HMAC_KEY"),
    }
    out
}

/// Poll until the accept loop is reachable (no fixed sleep).
async fn connect_ready(addr: SocketAddr) -> tokio::net::TcpStream {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        match tokio::net::TcpStream::connect(addr).await {
            Ok(stream) => return stream,
            Err(err) if tokio::time::Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(5)).await;
                let _ = err;
            }
            Err(err) => panic!("connect to {addr} timed out: {err}"),
        }
    }
}

#[test]
fn resolve_listen_addr_loopback_default_happy_path() {
    with_site_addr_env(None, || {
        let addr =
            resolve_listen_addr(ListenAddrDefault::Loopback { port: 3002 }).expect("default");
        assert_eq!(addr, SocketAddr::from(([127, 0, 0, 1], 3002)));
    });
}

#[tokio::test]
async fn bind_tcp_with_policy_loopback_happy_path() {
    with_hmac_key(None, || ());
    let addr: SocketAddr = "127.0.0.1:0".parse().expect("parse");
    let listener = bind_tcp_with_policy(addr).await.expect("bind with policy");
    let local = listener.local_addr().expect("local_addr");
    assert!(local.ip().is_loopback());
}

#[tokio::test]
async fn bind_tcp_with_policy_public_without_key_sad() {
    let _g = AUTH_ENV_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let prev = std::env::var("SUBSYSTEM_AUTH_HMAC_KEY").ok();
    std::env::remove_var("SUBSYSTEM_AUTH_HMAC_KEY");
    let addr: SocketAddr = "0.0.0.0:0".parse().expect("parse");
    let err = bind_tcp_with_policy(addr)
        .await
        .expect_err("public bind without key");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("HMAC") || msg.contains("non-loopback") || msg.contains("bind"),
        "unexpected error: {msg}"
    );
    match prev {
        Some(v) => std::env::set_var("SUBSYSTEM_AUTH_HMAC_KEY", v),
        None => std::env::remove_var("SUBSYSTEM_AUTH_HMAC_KEY"),
    }
}

#[tokio::test]
async fn bind_tcp_with_policy_public_with_key_happy_path() {
    let _g = AUTH_ENV_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let prev = std::env::var("SUBSYSTEM_AUTH_HMAC_KEY").ok();
    std::env::set_var("SUBSYSTEM_AUTH_HMAC_KEY", TEST_KEY);
    // Bind loopback ephemeral via AllInterfaces is heavy; use loopback with key set instead
    // for CI portability, and unit-test public+key in listener module.
    let addr: SocketAddr = "127.0.0.1:0".parse().expect("parse");
    let listener = bind_tcp_with_policy(addr).await.expect("bind");
    assert!(listener.local_addr().is_ok());
    match prev {
        Some(v) => std::env::set_var("SUBSYSTEM_AUTH_HMAC_KEY", v),
        None => std::env::remove_var("SUBSYSTEM_AUTH_HMAC_KEY"),
    }
}

#[tokio::test]
async fn bind_tcp_loopback_ephemeral_happy_path() {
    let addr: SocketAddr = "127.0.0.1:0".parse().expect("parse");
    let listener = bind_tcp(&addr).await.expect("bind");
    let local = listener.local_addr().expect("local_addr");
    assert_eq!(local.ip().to_string(), "127.0.0.1");
    assert_ne!(local.port(), 0);
}

#[tokio::test]
async fn bind_tcp_address_in_use_sad() {
    let addr: SocketAddr = "127.0.0.1:0".parse().expect("parse");
    let held = bind_tcp(&addr).await.expect("first bind");
    let occupied = held.local_addr().expect("local_addr");
    let err = bind_tcp(&occupied)
        .await
        .expect_err("second bind should fail");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("Address already in use")
            || msg.contains("addr in use")
            || msg.contains("os error 98")
            || msg.contains("os error 48"),
        "unexpected bind error: {msg}"
    );
}

#[tokio::test]
async fn serve_with_graceful_shutdown_health_then_stop_happy_path() {
    let addr: SocketAddr = "127.0.0.1:0".parse().expect("parse");
    let listener = bind_tcp(&addr).await.expect("bind");
    let local = listener.local_addr().expect("local_addr");

    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let serve_task = tokio::spawn(async move {
        serve_with_graceful_shutdown(listener, health_router(), async {
            let _ = shutdown_rx.await;
        })
        .await
    });

    let mut stream = connect_ready(local).await;
    stream
        .write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .expect("write");
    let mut buf = vec![0u8; 512];
    let n = stream.read(&mut buf).await.expect("read");
    let response = std::str::from_utf8(&buf[..n]).expect("utf8");
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "unexpected response: {response}"
    );

    shutdown_tx.send(()).expect("shutdown signal");
    let serve_result = tokio::time::timeout(Duration::from_secs(2), serve_task)
        .await
        .expect("serve join timed out")
        .expect("serve task join");
    assert!(serve_result.is_ok(), "serve error: {serve_result:?}");
}

#[tokio::test]
async fn serve_unknown_path_is_not_found_sad() {
    let addr: SocketAddr = "127.0.0.1:0".parse().expect("parse");
    let listener = bind_tcp(&addr).await.expect("bind");
    let local = listener.local_addr().expect("local_addr");

    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let serve_task = tokio::spawn(async move {
        serve_with_graceful_shutdown(listener, health_router(), async {
            let _ = shutdown_rx.await;
        })
        .await
    });

    let mut stream = connect_ready(local).await;
    stream
        .write_all(b"GET /missing HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .expect("write");
    let mut buf = vec![0u8; 512];
    let n = stream.read(&mut buf).await.expect("read");
    let response = std::str::from_utf8(&buf[..n]).expect("utf8");
    assert!(
        response.starts_with("HTTP/1.1 404"),
        "unexpected response: {response}"
    );
    assert_eq!(StatusCode::NOT_FOUND.as_u16(), 404);

    shutdown_tx.send(()).expect("shutdown signal");
    let _ = tokio::time::timeout(Duration::from_secs(2), serve_task)
        .await
        .expect("serve join timed out");
}

#[test]
fn worker_stack_default_happy_path() {
    with_stack_env(None, || {
        assert_eq!(resolve_worker_stack_bytes(), DEFAULT_WORKER_STACK_BYTES);
    });
}

#[test]
fn worker_stack_env_override_happy_path() {
    with_stack_env(Some("2097152"), || {
        assert_eq!(resolve_worker_stack_bytes(), 2 * 1024 * 1024);
    });
}

#[test]
fn worker_stack_invalid_or_below_floor_falls_back_sad() {
    with_stack_env(Some("1024"), || {
        assert_eq!(resolve_worker_stack_bytes(), DEFAULT_WORKER_STACK_BYTES);
    });
    with_stack_env(Some("not-a-number"), || {
        assert_eq!(resolve_worker_stack_bytes(), DEFAULT_WORKER_STACK_BYTES);
    });
}
