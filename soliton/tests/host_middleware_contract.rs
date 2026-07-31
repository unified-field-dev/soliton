//! Request-extension middleware contracts.
//!
//! Test-only binary; exempt from library `missing_docs` deny.
#![allow(missing_docs)]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Extensions, Request, StatusCode};
use axum::middleware::from_fn_with_state;
use axum::routing::get;
use axum::Router;
use soliton::middleware::{attach_request_extensions, RequestExtensionState};
use tower::ServiceExt;

#[derive(Clone)]
struct TestState {
    counter: Arc<AtomicUsize>,
}

impl RequestExtensionState for TestState {
    fn inject_request_extensions(&self, extensions: &mut Extensions) {
        extensions.insert(Arc::clone(&self.counter));
    }
}

/// Implements the trait but inserts nothing — proves Soliton middleware ran without
/// satisfying a handler that requires `Extension<T>`.
#[derive(Clone)]
struct EmptyInjectState;

impl RequestExtensionState for EmptyInjectState {
    fn inject_request_extensions(&self, _extensions: &mut Extensions) {}
}

#[tokio::test]
async fn attach_request_extensions_injects_before_handler_happy_path() {
    let counter = Arc::new(AtomicUsize::new(0));
    let state = TestState {
        counter: Arc::clone(&counter),
    };

    let app = Router::new()
        .route(
            "/",
            get(|ext: axum::Extension<Arc<AtomicUsize>>| async move {
                ext.0.fetch_add(1, Ordering::SeqCst);
                StatusCode::OK
            }),
        )
        .layer(from_fn_with_state(
            state,
            attach_request_extensions::<TestState>,
        ));

    let response = app
        .oneshot(
            Request::builder()
                .uri("/")
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("oneshot");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(counter.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn attach_without_required_extension_rejects_extractor_sad() {
    let app = Router::new()
        .route(
            "/",
            get(|ext: axum::Extension<Arc<AtomicUsize>>| async move {
                let _ = ext;
                StatusCode::OK
            }),
        )
        .layer(from_fn_with_state(
            EmptyInjectState,
            attach_request_extensions::<EmptyInjectState>,
        ));

    let response = app
        .oneshot(
            Request::builder()
                .uri("/")
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("oneshot");
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}
