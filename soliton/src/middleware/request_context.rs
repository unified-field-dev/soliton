use axum::extract::State as AxumState;
use axum::http::{Extensions, Request};
use axum::middleware::Next;
use axum::response::IntoResponse;

/// App state that can populate Axum request extensions before handlers run.
///
/// Host wiring crates implement this to inject database handles, request context,
/// or other engine-specific types without this crate depending on those engines.
///
/// # Examples
///
/// ```rust,no_run
/// use axum::http::Extensions;
/// use soliton::middleware::RequestExtensionState;
///
/// #[derive(Clone)]
/// struct AppState {
///     // …
/// }
///
/// impl RequestExtensionState for AppState {
///     fn inject_request_extensions(&self, extensions: &mut Extensions) {
///         let _ = extensions;
///     }
/// }
/// ```
pub trait RequestExtensionState: Clone + Send + Sync + 'static {
    /// Insert host-owned values into `extensions` (typically `Clone` handles).
    ///
    /// # Contract
    ///
    /// - Called once per request, before the rest of the middleware/handler chain.
    /// - Insert values handlers will extract (for example `Extension<T>`); prefer cheap
    ///   `Clone` handles over large owned data.
    /// - Must not assume prior extension keys from other layers unless the host ordered them.
    fn inject_request_extensions(&self, extensions: &mut Extensions);
}

/// Axum middleware that calls [`RequestExtensionState::inject_request_extensions`] on each request.
///
/// Wire with `from_fn_with_state(state, attach_request_extensions::<S>)` and ensure the
/// router carries that same state (or layer above `with_state` as appropriate for Axum 0.8).
///
/// # Examples
///
/// See the [`crate::middleware`] module example, or
/// `cargo run -p soliton --example process_host`.
pub async fn attach_request_extensions<S>(
    AxumState(app_state): AxumState<S>,
    mut req: Request<axum::body::Body>,
    next: Next,
) -> impl IntoResponse
where
    S: RequestExtensionState,
{
    app_state.inject_request_extensions(req.extensions_mut());
    next.run(req).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::middleware::from_fn_with_state;
    use axum::routing::get;
    use axum::Router;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
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

    #[tokio::test]
    async fn injects_extensions_before_handler_happy_path() {
        let counter = Arc::new(AtomicUsize::new(0));
        let state = TestState {
            counter: Arc::clone(&counter),
        };

        let app = Router::new()
            .route(
                "/",
                get(|ext: axum::Extension<Arc<AtomicUsize>>| async move {
                    ext.0.fetch_add(1, Ordering::SeqCst);
                    "ok"
                }),
            )
            .layer(from_fn_with_state(
                state.clone(),
                attach_request_extensions::<TestState>,
            ));

        let response = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert!(response.status().is_success());
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }
}
