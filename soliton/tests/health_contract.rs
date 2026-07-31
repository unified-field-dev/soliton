//! Health router public contract (oneshot, no listen socket).
//!
//! Test-only binary; exempt from library `missing_docs` deny.
#![allow(missing_docs)]

use axum::body::Body;
use axum::http::{Request, StatusCode};
use soliton::health_router;
use tower::ServiceExt;

#[tokio::test]
async fn health_get_returns_ok_happy_path() {
    let app = health_router();
    let response = app
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("oneshot");
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn unknown_path_is_not_found_sad() {
    let app = health_router();
    let response = app
        .oneshot(
            Request::builder()
                .uri("/not-health")
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("oneshot");
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}
