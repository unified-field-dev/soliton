//! Multi-thread Tokio runtime helper with a configurable per-worker stack.
//!
//! Host binaries often compose deeply nested async stacks. On Linux the default ~2 MiB
//! worker stack can overflow in debug builds. [`run()`] uses **8 MiB** per worker by default;
//! override via [`WORKER_STACK_ENV`] (`SOLITON_WORKER_STACK_BYTES`).
//!
//! # Concern → API
//!
//! | Concern | API |
//! |---------|-----|
//! | Drive `async` host `main` with enlarged worker stacks | [`run()`] |
//! | Resolve stack size (env or default) | [`resolve_worker_stack_bytes()`] |
//! | Default / env constant | [`DEFAULT_WORKER_STACK_BYTES`], [`WORKER_STACK_ENV`] |
//!
//! # Examples
//!
//! ```rust,no_run
//! fn main() -> anyhow::Result<()> {
//!     soliton::tokio_runtime::run(async {
//!         // resolve → bind → serve …
//!         Ok::<(), anyhow::Error>(())
//!     })
//! }
//! ```
//!
//! Runnable: `cargo run -p soliton --example process_host`
//!
//! [`run()`]: crate::tokio_runtime::run
//! [`resolve_worker_stack_bytes()`]: crate::tokio_runtime::resolve_worker_stack_bytes
//! [`DEFAULT_WORKER_STACK_BYTES`]: crate::tokio_runtime::DEFAULT_WORKER_STACK_BYTES
//! [`WORKER_STACK_ENV`]: crate::tokio_runtime::WORKER_STACK_ENV

use std::future::Future;

/// Default per-worker stack size (8 MiB) for soliton-hosted server binaries.
pub const DEFAULT_WORKER_STACK_BYTES: usize = 8 * 1024 * 1024;

/// Env var that overrides [`DEFAULT_WORKER_STACK_BYTES`] (decimal bytes).
pub const WORKER_STACK_ENV: &str = "SOLITON_WORKER_STACK_BYTES";

/// Resolve the per-worker stack size from env, falling back to
/// [`DEFAULT_WORKER_STACK_BYTES`].
///
/// Values below 1 MiB, or non-decimal strings, emit a [`tracing`] warning and use the default.
/// Hosts own the tracing subscriber; without one these events are no-ops.
#[must_use]
pub fn resolve_worker_stack_bytes() -> usize {
    std::env::var(WORKER_STACK_ENV).map_or(DEFAULT_WORKER_STACK_BYTES, |s| {
        match s.trim().parse::<usize>() {
            Ok(n) if n >= 1024 * 1024 => n,
            Ok(n) => {
                tracing::warn!(
                    env = WORKER_STACK_ENV,
                    value_bytes = n,
                    default_bytes = DEFAULT_WORKER_STACK_BYTES,
                    "soliton worker stack env below 1 MiB floor; using default"
                );
                DEFAULT_WORKER_STACK_BYTES
            }
            Err(_e) => {
                tracing::warn!(
                    env = WORKER_STACK_ENV,
                    default_bytes = DEFAULT_WORKER_STACK_BYTES,
                    "soliton worker stack env is not a valid byte count; using default"
                );
                DEFAULT_WORKER_STACK_BYTES
            }
        }
    })
}

/// Build a multi-thread Tokio runtime with the resolved worker stack size and
/// drive `future` to completion.
///
/// Replacement for `#[tokio::main]` in soliton-hosted binaries.
///
/// # Panics
///
/// Panics if the Tokio multi-thread runtime cannot be built (misconfiguration / OOM).
/// That failure is not recoverable in-process for a host binary.
///
/// # Examples
///
/// ```rust,no_run
/// fn main() -> anyhow::Result<()> {
///     soliton::tokio_runtime::run(async {
///         Ok::<(), anyhow::Error>(())
///     })
/// }
/// ```
pub fn run<F, T>(future: F) -> T
where
    F: Future<Output = T>,
{
    let stack_bytes = resolve_worker_stack_bytes();
    match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_stack_size(stack_bytes)
        .thread_name("soliton-runtime-worker")
        .build()
    {
        Ok(runtime) => runtime.block_on(future),
        // Runtime builder failure is a host misconfiguration / OOM — not recoverable in-process.
        Err(err) => panic!("build tokio multi-thread runtime: {err}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static STACK_ENV_LOCK: Mutex<()> = Mutex::new(());

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

    #[test]
    fn default_stack_when_env_missing_happy_path() {
        with_stack_env(None, || {
            assert_eq!(resolve_worker_stack_bytes(), DEFAULT_WORKER_STACK_BYTES);
        });
    }

    #[test]
    fn parses_valid_env_override_happy_path() {
        with_stack_env(Some("16777216"), || {
            assert_eq!(resolve_worker_stack_bytes(), 16 * 1024 * 1024);
        });
    }

    #[test]
    fn below_floor_and_invalid_fall_back_to_default() {
        with_stack_env(Some("1024"), || {
            assert_eq!(resolve_worker_stack_bytes(), DEFAULT_WORKER_STACK_BYTES);
        });
        with_stack_env(Some("not-a-number"), || {
            assert_eq!(resolve_worker_stack_bytes(), DEFAULT_WORKER_STACK_BYTES);
        });
    }
}
