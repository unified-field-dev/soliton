//! Optional subsystem HMAC middleware contracts (oneshot).
//!
//! Test-only binary; exempt from library `missing_docs` deny.
//! Env-mutating tests hold a process-wide lock across awaits so keys stay stable.
#![allow(missing_docs)]
#![allow(clippy::await_holding_lock)]

use std::sync::Mutex;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::middleware::from_fn;
use axum::routing::{get, post};
use axum::Router;
use soliton::subsystem_auth::{
    axum_optional_subsystem_hmac, load_hmac_key_material_from_env, subsystem_hmac_header_pair,
    SUBSYSTEM_AUTH_HEADER_NAME,
};
use tower::ServiceExt;

static HMAC_ENV_LOCK: Mutex<()> = Mutex::new(());

/// 32-byte UTF-8 test key.
const TEST_KEY: &str = "soliton-test-hmac-key-32-bytes!!";

fn with_hmac_env<R>(value: Option<&str>, f: impl FnOnce() -> R) -> R {
    let _g = HMAC_ENV_LOCK
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

fn api_app() -> Router {
    Router::new()
        .route("/api/echo", post(|| async { StatusCode::OK }))
        .route("/api/ping", get(|| async { StatusCode::OK }))
        .route("/api", get(|| async { StatusCode::OK }))
        .route(
            "/__handoff_internal/x",
            get(|| async { StatusCode::OK }).post(|| async { StatusCode::OK }),
        )
        .route("/__handoff_internal", get(|| async { StatusCode::OK }))
        .route("/health", get(|| async { StatusCode::OK }))
        .route("/public", get(|| async { StatusCode::OK }))
        .route("/internal/ok", get(|| async { StatusCode::OK }))
        .layer(from_fn(axum_optional_subsystem_hmac))
}

#[test]
fn load_hmac_key_utf8_happy_path() {
    with_hmac_env(Some(TEST_KEY), || {
        assert_eq!(
            load_hmac_key_material_from_env().as_deref(),
            Some(TEST_KEY.as_bytes())
        );
    });
}

#[test]
fn load_hmac_key_empty_or_bad_hex_or_short_sad() {
    with_hmac_env(None, || {
        assert!(load_hmac_key_material_from_env().is_none());
    });
    with_hmac_env(Some("   "), || {
        assert!(load_hmac_key_material_from_env().is_none());
    });
    with_hmac_env(Some("hex:zz"), || {
        assert!(load_hmac_key_material_from_env().is_none());
    });
    with_hmac_env(Some("dev-secret"), || {
        assert!(load_hmac_key_material_from_env().is_none());
    });
}

#[tokio::test]
async fn hmac_valid_api_request_happy_path() {
    let _g = HMAC_ENV_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let prev = std::env::var("SUBSYSTEM_AUTH_HMAC_KEY").ok();
    std::env::set_var("SUBSYSTEM_AUTH_HMAC_KEY", TEST_KEY);

    let body = br#"{"ok":true}"#;
    let (name, tag) = subsystem_hmac_header_pair("POST", "/api/echo", body)
        .expect("header pair with key configured");
    assert_eq!(name, SUBSYSTEM_AUTH_HEADER_NAME);

    let app = api_app();
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/echo")
                .header(SUBSYSTEM_AUTH_HEADER_NAME, tag)
                .body(Body::from(body.as_slice()))
                .expect("build request"),
        )
        .await
        .expect("oneshot");
    assert_eq!(response.status(), StatusCode::OK);

    match prev {
        Some(v) => std::env::set_var("SUBSYSTEM_AUTH_HMAC_KEY", v),
        None => std::env::remove_var("SUBSYSTEM_AUTH_HMAC_KEY"),
    }
}

#[tokio::test]
async fn hmac_exact_api_root_enforced_sad() {
    let _g = HMAC_ENV_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let prev = std::env::var("SUBSYSTEM_AUTH_HMAC_KEY").ok();
    std::env::set_var("SUBSYSTEM_AUTH_HMAC_KEY", TEST_KEY);

    let app = api_app();
    let missing = app
        .oneshot(
            Request::builder()
                .uri("/api")
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("oneshot");
    assert_eq!(missing.status(), StatusCode::UNAUTHORIZED);

    match prev {
        Some(v) => std::env::set_var("SUBSYSTEM_AUTH_HMAC_KEY", v),
        None => std::env::remove_var("SUBSYSTEM_AUTH_HMAC_KEY"),
    }
}

#[tokio::test]
async fn hmac_exact_handoff_root_enforced_sad() {
    let _g = HMAC_ENV_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let prev = std::env::var("SUBSYSTEM_AUTH_HMAC_KEY").ok();
    std::env::set_var("SUBSYSTEM_AUTH_HMAC_KEY", TEST_KEY);

    let app = api_app();
    let missing = app
        .oneshot(
            Request::builder()
                .uri("/__handoff_internal")
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("oneshot");
    assert_eq!(missing.status(), StatusCode::UNAUTHORIZED);

    match prev {
        Some(v) => std::env::set_var("SUBSYSTEM_AUTH_HMAC_KEY", v),
        None => std::env::remove_var("SUBSYSTEM_AUTH_HMAC_KEY"),
    }
}

#[tokio::test]
async fn hmac_missing_or_bad_tag_returns_auth_errors_sad() {
    let _g = HMAC_ENV_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let prev = std::env::var("SUBSYSTEM_AUTH_HMAC_KEY").ok();
    std::env::set_var("SUBSYSTEM_AUTH_HMAC_KEY", TEST_KEY);

    let app = api_app();
    let missing = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/ping")
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("oneshot");
    assert_eq!(missing.status(), StatusCode::UNAUTHORIZED);

    let bad = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/ping")
                .header(SUBSYSTEM_AUTH_HEADER_NAME, "00")
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("oneshot");
    assert_eq!(bad.status(), StatusCode::FORBIDDEN);

    match prev {
        Some(v) => std::env::set_var("SUBSYSTEM_AUTH_HMAC_KEY", v),
        None => std::env::remove_var("SUBSYSTEM_AUTH_HMAC_KEY"),
    }
}

#[tokio::test]
async fn hmac_unset_key_rejects_api_by_default_sad() {
    let _g = HMAC_ENV_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let prev_key = std::env::var("SUBSYSTEM_AUTH_HMAC_KEY").ok();
    std::env::remove_var("SUBSYSTEM_AUTH_HMAC_KEY");

    let app = api_app();
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/ping")
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("oneshot");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    match prev_key {
        Some(v) => std::env::set_var("SUBSYSTEM_AUTH_HMAC_KEY", v),
        None => std::env::remove_var("SUBSYSTEM_AUTH_HMAC_KEY"),
    }
}

#[tokio::test]
async fn hmac_short_key_rejects_api_sad() {
    let _g = HMAC_ENV_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let prev_key = std::env::var("SUBSYSTEM_AUTH_HMAC_KEY").ok();
    std::env::set_var("SUBSYSTEM_AUTH_HMAC_KEY", "dev-secret");

    let app = api_app();
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/ping")
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("oneshot");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    match prev_key {
        Some(v) => std::env::set_var("SUBSYSTEM_AUTH_HMAC_KEY", v),
        None => std::env::remove_var("SUBSYSTEM_AUTH_HMAC_KEY"),
    }
}

#[tokio::test]
async fn hmac_bypasses_health_and_internal_happy_path() {
    let _g = HMAC_ENV_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let prev = std::env::var("SUBSYSTEM_AUTH_HMAC_KEY").ok();
    std::env::set_var("SUBSYSTEM_AUTH_HMAC_KEY", TEST_KEY);

    let app = api_app();
    for uri in ["/health", "/internal/ok", "/public"] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(uri)
                    .body(Body::empty())
                    .expect("build request"),
            )
            .await
            .expect("oneshot");
        assert_eq!(response.status(), StatusCode::OK, "uri={uri}");
    }

    match prev {
        Some(v) => std::env::set_var("SUBSYSTEM_AUTH_HMAC_KEY", v),
        None => std::env::remove_var("SUBSYSTEM_AUTH_HMAC_KEY"),
    }
}

#[tokio::test]
async fn hmac_handoff_valid_request_happy_path() {
    let _g = HMAC_ENV_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let prev = std::env::var("SUBSYSTEM_AUTH_HMAC_KEY").ok();
    std::env::set_var("SUBSYSTEM_AUTH_HMAC_KEY", TEST_KEY);

    let (name, tag) = subsystem_hmac_header_pair("GET", "/__handoff_internal/x", b"")
        .expect("header pair with key configured");
    assert_eq!(name, SUBSYSTEM_AUTH_HEADER_NAME);

    let app = api_app();
    let response = app
        .oneshot(
            Request::builder()
                .uri("/__handoff_internal/x")
                .header(SUBSYSTEM_AUTH_HEADER_NAME, tag)
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("oneshot");
    assert_eq!(response.status(), StatusCode::OK);

    match prev {
        Some(v) => std::env::set_var("SUBSYSTEM_AUTH_HMAC_KEY", v),
        None => std::env::remove_var("SUBSYSTEM_AUTH_HMAC_KEY"),
    }
}

#[tokio::test]
async fn hmac_handoff_missing_or_bad_tag_returns_auth_errors_sad() {
    let _g = HMAC_ENV_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let prev = std::env::var("SUBSYSTEM_AUTH_HMAC_KEY").ok();
    std::env::set_var("SUBSYSTEM_AUTH_HMAC_KEY", TEST_KEY);

    let app = api_app();
    let missing = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/__handoff_internal/x")
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("oneshot");
    assert_eq!(missing.status(), StatusCode::UNAUTHORIZED);

    let bad = app
        .oneshot(
            Request::builder()
                .uri("/__handoff_internal/x")
                .header(SUBSYSTEM_AUTH_HEADER_NAME, "00")
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("oneshot");
    assert_eq!(bad.status(), StatusCode::FORBIDDEN);

    match prev {
        Some(v) => std::env::set_var("SUBSYSTEM_AUTH_HMAC_KEY", v),
        None => std::env::remove_var("SUBSYSTEM_AUTH_HMAC_KEY"),
    }
}

#[tokio::test]
async fn hmac_oversized_body_returns_400_sad() {
    let _g = HMAC_ENV_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let prev = std::env::var("SUBSYSTEM_AUTH_HMAC_KEY").ok();
    std::env::set_var("SUBSYSTEM_AUTH_HMAC_KEY", TEST_KEY);

    // Middleware buffers at most 4 MiB; one byte over forces body_unreadable → 400.
    let oversized = vec![0u8; 4 * 1024 * 1024 + 1];
    let (_name, tag) =
        subsystem_hmac_header_pair("POST", "/api/echo", &oversized).expect("header pair");

    let app = api_app();
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/echo")
                .header(SUBSYSTEM_AUTH_HEADER_NAME, tag)
                .body(Body::from(oversized))
                .expect("build request"),
        )
        .await
        .expect("oneshot");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    match prev {
        Some(v) => std::env::set_var("SUBSYSTEM_AUTH_HMAC_KEY", v),
        None => std::env::remove_var("SUBSYSTEM_AUTH_HMAC_KEY"),
    }
}
