//! Per-request state injection for Axum apps (engine-agnostic).
//!
//! Hosts implement [`RequestExtensionState`] and layer [`attach_request_extensions`] so
//! handlers can extract injected values via `axum::Extension<T>` without this crate
//! depending on concrete engine types.
//!
//! # Concern → API
//!
//! | Concern | API |
//! |---------|-----|
//! | Declare what to inject per request | [`RequestExtensionState`] |
//! | Axum middleware that performs the inject | [`attach_request_extensions`] |
//!
//! # Examples
//!
//! ```rust,no_run
//! use axum::middleware::from_fn_with_state;
//! use axum::Router;
//! use soliton::middleware::{attach_request_extensions, RequestExtensionState};
//!
//! #[derive(Clone)]
//! struct AppState {
//!     // host handles (DB pool, request context builders, …)
//! }
//!
//! impl RequestExtensionState for AppState {
//!     fn inject_request_extensions(&self, extensions: &mut axum::http::Extensions) {
//!         // extensions.insert(…);
//!         let _ = extensions;
//!     }
//! }
//!
//! let app: Router<()> = Router::new().layer(from_fn_with_state(
//!     AppState {},
//!     attach_request_extensions::<AppState>,
//! ));
//! let _ = app;
//! ```
//!
//! Runnable: `cargo run -p soliton --example process_host`
//!
//! [`RequestExtensionState`]: crate::middleware::RequestExtensionState
//! [`attach_request_extensions`]: crate::middleware::attach_request_extensions

/// See [`RequestExtensionState`] and [`attach_request_extensions`].
pub mod request_context;

pub use request_context::{attach_request_extensions, RequestExtensionState};
