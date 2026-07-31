//! Listen-address resolution, bind policy, and TCP bind helpers.
//!
//! Resolve a [`std::net::SocketAddr`] from env (or an explicit default), refuse non-loopback binds
//! without an HMAC key, and bind a Tokio TCP listener for [`crate::serve`].
//!
//! # Concern → API
//!
//! | Concern | API |
//! |---------|-----|
//! | Strict resolve (`LEPTOS_SITE_ADDR` → `SITE_ADDR` → default) | [`resolve_listen_addr`], [`ListenAddrDefault`] |
//! | Non-loopback requires HMAC key presence | [`ensure_bind_allowed`] |
//! | Bind with policy then Tokio listener | [`bind_tcp_with_policy`] |
//! | Bind Tokio listener (no policy) | [`bind_tcp`] |
//! | Typed resolve / bind-policy failures | [`crate::ListenAddrError`], [`crate::BindPolicyError`] |
//!
//! # Examples
//!
//! ```rust,no_run
//! use soliton::listener::{bind_tcp_with_policy, resolve_listen_addr, ListenAddrDefault};
//! use soliton::serve;
//! use axum::Router;
//!
//! # async fn demo() -> anyhow::Result<()> {
//! let addr = resolve_listen_addr(ListenAddrDefault::Loopback { port: 3002 })?;
//! let listener = bind_tcp_with_policy(addr).await?;
//! serve(listener, Router::new()).await?;
//! # Ok(())
//! # }
//! ```
//!
//! Runnable: `cargo run -p soliton --example process_host`
//!
//! [`resolve_listen_addr`]: crate::listener::resolve_listen_addr
//! [`ListenAddrDefault`]: crate::listener::ListenAddrDefault
//! [`ensure_bind_allowed`]: crate::listener::ensure_bind_allowed
//! [`bind_tcp_with_policy`]: crate::listener::bind_tcp_with_policy
//! [`bind_tcp`]: crate::listener::bind_tcp

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use crate::error::{BindPolicyError, ListenAddrError};
use crate::subsystem_auth::load_hmac_key_material_from_env;

/// Default listen address when neither `LEPTOS_SITE_ADDR` nor `SITE_ADDR` is set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub enum ListenAddrDefault {
    /// `127.0.0.1:{port}` — preferred for local/embedded hosts.
    Loopback {
        /// TCP port.
        port: u16,
    },
    /// `0.0.0.0:{port}` — preferred for fleet apps that intentionally expose all interfaces.
    AllInterfaces {
        /// TCP port.
        port: u16,
    },
}

impl ListenAddrDefault {
    fn socket_addr(self) -> SocketAddr {
        match self {
            Self::Loopback { port } => SocketAddr::from(([127, 0, 0, 1], port)),
            Self::AllInterfaces { port } => {
                SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port)
            }
        }
    }
}

/// Resolve listen address: `LEPTOS_SITE_ADDR`, then `SITE_ADDR`, then `default`.
///
/// Invalid or non-Unicode env values return [`ListenAddrError`] (no silent fallback).
/// Display of that error includes the variable **name** only — never the raw value.
///
/// # Errors
///
/// Returns [`ListenAddrError`] when an env var is set but unusable.
///
/// # Examples
///
/// ```rust
/// use soliton::listener::{resolve_listen_addr, ListenAddrDefault};
///
/// let addr = resolve_listen_addr(ListenAddrDefault::Loopback { port: 3002 }).expect("default");
/// assert!(addr.ip().is_loopback());
/// assert_eq!(addr.port(), 3002);
/// ```
pub fn resolve_listen_addr(default: ListenAddrDefault) -> Result<SocketAddr, ListenAddrError> {
    let result = match read_addr_env("LEPTOS_SITE_ADDR") {
        Ok(Some(addr)) => Ok(addr),
        Ok(None) => match read_addr_env("SITE_ADDR") {
            Ok(Some(addr)) => Ok(addr),
            Ok(None) => Ok(default.socket_addr()),
            Err(e) => Err(e),
        },
        Err(e) => Err(e),
    };
    match &result {
        Ok(addr) => tracing::debug!(%addr, "soliton listen addr resolved"),
        Err(err) => tracing::warn!(error = %err, "soliton listen addr resolve failed"),
    }
    result
}

fn read_addr_env(var: &'static str) -> Result<Option<SocketAddr>, ListenAddrError> {
    match std::env::var(var) {
        Ok(value) => {
            let trimmed = value.trim();
            trimmed
                .parse()
                .map(Some)
                .map_err(|_| ListenAddrError::InvalidSocketAddr { var })
        }
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => Err(ListenAddrError::EnvNotUnicode { var }),
    }
}

/// Refuse non-loopback binds when `SUBSYSTEM_AUTH_HMAC_KEY` is unset or unusable.
///
/// Checks key **presence** only (via [`load_hmac_key_material_from_env`]); never
/// logs or returns key material. Presence does not prove HMAC middleware is layered.
///
/// # Errors
///
/// Returns [`BindPolicyError::NonLoopbackWithoutHmacKey`] when `addr` is not
/// loopback and the HMAC key env var is missing/empty/too short.
///
/// # Examples
///
/// ```rust
/// use std::net::SocketAddr;
/// use soliton::listener::ensure_bind_allowed;
///
/// let loopback: SocketAddr = "127.0.0.1:3002".parse().unwrap();
/// ensure_bind_allowed(loopback).expect("loopback always allowed");
/// ```
#[must_use = "ignoring bind policy skips a security gate"]
pub fn ensure_bind_allowed(addr: SocketAddr) -> Result<(), BindPolicyError> {
    if addr.ip().is_loopback() {
        return Ok(());
    }
    if load_hmac_key_material_from_env().is_some() {
        return Ok(());
    }
    let err = BindPolicyError::NonLoopbackWithoutHmacKey { addr };
    tracing::warn!(%addr, error = %err, "soliton bind policy refused");
    Err(err)
}

/// Apply [`ensure_bind_allowed`], then [`bind_tcp`].
///
/// Prefer this for subsystem process hosts that may bind non-loopback addresses.
/// SSR shells that already enforce their own bind policy may call [`bind_tcp`] directly
/// after an explicit [`ensure_bind_allowed`].
///
/// # Errors
///
/// Returns [`BindPolicyError`] when the address is refused, or an I/O error when bind fails.
///
/// # Examples
///
/// ```rust,no_run
/// use soliton::listener::{bind_tcp_with_policy, resolve_listen_addr, ListenAddrDefault};
///
/// # async fn demo() -> anyhow::Result<()> {
/// let addr = resolve_listen_addr(ListenAddrDefault::Loopback { port: 0 })?;
/// let listener = bind_tcp_with_policy(addr).await?;
/// let _ = listener;
/// # Ok(())
/// # }
/// ```
pub async fn bind_tcp_with_policy(addr: SocketAddr) -> anyhow::Result<tokio::net::TcpListener> {
    ensure_bind_allowed(addr)?;
    bind_tcp(&addr).await
}

/// Bind a Tokio [`TcpListener`](tokio::net::TcpListener) to `addr`.
///
/// Does **not** call [`ensure_bind_allowed`]. Prefer [`bind_tcp_with_policy`] for
/// subsystem hosts.
///
/// # Errors
///
/// Returns an error when the OS cannot bind the address.
///
/// # Examples
///
/// ```rust,no_run
/// use soliton::listener::{bind_tcp, ensure_bind_allowed, resolve_listen_addr, ListenAddrDefault};
///
/// # async fn demo() -> anyhow::Result<()> {
/// let addr = resolve_listen_addr(ListenAddrDefault::Loopback { port: 0 })?;
/// ensure_bind_allowed(addr)?;
/// let listener = bind_tcp(&addr).await?;
/// let _ = listener;
/// # Ok(())
/// # }
/// ```
pub async fn bind_tcp(addr: &SocketAddr) -> anyhow::Result<tokio::net::TcpListener> {
    match tokio::net::TcpListener::bind(addr).await {
        Ok(listener) => {
            let local = listener.local_addr().unwrap_or(*addr);
            tracing::info!(%local, requested = %addr, "soliton tcp bind ok");
            Ok(listener)
        }
        Err(err) => {
            tracing::error!(%addr, error = %err, "soliton tcp bind failed");
            Err(err.into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static SITE_ADDR_LOCK: Mutex<()> = Mutex::new(());
    static AUTH_ENV_LOCK: Mutex<()> = Mutex::new(());

    const TEST_KEY: &str = "soliton-test-hmac-key-32-bytes!!";

    fn with_addr_env<R>(leptos: Option<&str>, site: Option<&str>, f: impl FnOnce() -> R) -> R {
        let _g = SITE_ADDR_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let prev_l = std::env::var("LEPTOS_SITE_ADDR").ok();
        let prev_s = std::env::var("SITE_ADDR").ok();
        match leptos {
            Some(v) => std::env::set_var("LEPTOS_SITE_ADDR", v),
            None => std::env::remove_var("LEPTOS_SITE_ADDR"),
        }
        match site {
            Some(v) => std::env::set_var("SITE_ADDR", v),
            None => std::env::remove_var("SITE_ADDR"),
        }
        let out = f();
        match prev_l {
            Some(v) => std::env::set_var("LEPTOS_SITE_ADDR", v),
            None => std::env::remove_var("LEPTOS_SITE_ADDR"),
        }
        match prev_s {
            Some(v) => std::env::set_var("SITE_ADDR", v),
            None => std::env::remove_var("SITE_ADDR"),
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

    #[test]
    fn resolve_loopback_default_happy_path() {
        with_addr_env(None, None, || {
            let addr =
                resolve_listen_addr(ListenAddrDefault::Loopback { port: 3002 }).expect("default");
            assert_eq!(addr, SocketAddr::from(([127, 0, 0, 1], 3002)));
        });
    }

    #[test]
    fn resolve_all_interfaces_default_happy_path() {
        with_addr_env(None, None, || {
            let addr = resolve_listen_addr(ListenAddrDefault::AllInterfaces { port: 3000 })
                .expect("default");
            assert_eq!(addr, SocketAddr::from(([0, 0, 0, 0], 3000)));
        });
    }

    #[test]
    fn resolve_leptos_precedes_site_happy_path() {
        with_addr_env(Some("127.0.0.1:4100"), Some("127.0.0.1:4200"), || {
            let addr =
                resolve_listen_addr(ListenAddrDefault::Loopback { port: 3000 }).expect("resolve");
            assert_eq!(addr, "127.0.0.1:4100".parse().unwrap());
        });
    }

    #[test]
    fn resolve_site_addr_when_leptos_absent_happy_path() {
        with_addr_env(None, Some("127.0.0.1:4300"), || {
            let addr =
                resolve_listen_addr(ListenAddrDefault::Loopback { port: 3000 }).expect("resolve");
            assert_eq!(addr, "127.0.0.1:4300".parse().unwrap());
        });
    }

    #[test]
    fn resolve_invalid_env_errors_without_echoing_value_sad() {
        with_addr_env(Some("not-an-addr"), None, || {
            let err = resolve_listen_addr(ListenAddrDefault::Loopback { port: 3000 })
                .expect_err("invalid");
            assert_eq!(
                err,
                ListenAddrError::InvalidSocketAddr {
                    var: "LEPTOS_SITE_ADDR"
                }
            );
            let msg = err.to_string();
            assert!(msg.contains("LEPTOS_SITE_ADDR"));
            assert!(!msg.contains("not-an-addr"));
        });
    }

    #[test]
    fn resolve_invalid_site_addr_when_leptos_absent_sad() {
        with_addr_env(None, Some("not-an-addr"), || {
            let err = resolve_listen_addr(ListenAddrDefault::Loopback { port: 3000 })
                .expect_err("invalid SITE_ADDR");
            assert_eq!(err, ListenAddrError::InvalidSocketAddr { var: "SITE_ADDR" });
            let msg = err.to_string();
            assert!(msg.contains("SITE_ADDR"));
            assert!(!msg.contains("not-an-addr"));
        });
    }

    #[test]
    fn resolve_invalid_leptos_does_not_fall_back_to_site_sad() {
        with_addr_env(Some("not-an-addr"), Some("127.0.0.1:4300"), || {
            let err = resolve_listen_addr(ListenAddrDefault::Loopback { port: 3000 })
                .expect_err("invalid LEPTOS must not fall back");
            assert_eq!(
                err,
                ListenAddrError::InvalidSocketAddr {
                    var: "LEPTOS_SITE_ADDR"
                }
            );
            assert!(!err.to_string().contains("not-an-addr"));
            assert!(!err.to_string().contains("127.0.0.1:4300"));
        });
    }

    #[cfg(unix)]
    #[test]
    fn resolve_non_unicode_env_sad() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;

        let _g = SITE_ADDR_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let prev_l = std::env::var_os("LEPTOS_SITE_ADDR");
        let prev_s = std::env::var_os("SITE_ADDR");
        std::env::remove_var("SITE_ADDR");
        // Invalid UTF-8 bytes — not representable as Rust `String`.
        std::env::set_var(
            "LEPTOS_SITE_ADDR",
            OsString::from_vec(vec![0xff, 0xfe, 0xfd]),
        );

        let err = resolve_listen_addr(ListenAddrDefault::Loopback { port: 3000 })
            .expect_err("non-unicode");
        assert_eq!(
            err,
            ListenAddrError::EnvNotUnicode {
                var: "LEPTOS_SITE_ADDR"
            }
        );
        assert!(err.to_string().contains("LEPTOS_SITE_ADDR"));

        match prev_l {
            Some(v) => std::env::set_var("LEPTOS_SITE_ADDR", v),
            None => std::env::remove_var("LEPTOS_SITE_ADDR"),
        }
        match prev_s {
            Some(v) => std::env::set_var("SITE_ADDR", v),
            None => std::env::remove_var("SITE_ADDR"),
        }
    }

    #[test]
    fn ensure_bind_loopback_ok_happy_path() {
        with_hmac_key(None, || {
            ensure_bind_allowed("127.0.0.1:3002".parse().unwrap()).expect("loopback");
        });
    }

    #[test]
    fn ensure_bind_ipv6_loopback_ok_happy_path() {
        with_hmac_key(None, || {
            ensure_bind_allowed("[::1]:3002".parse().unwrap()).expect("ipv6 loopback");
        });
    }

    #[test]
    fn ensure_bind_public_with_key_ok_happy_path() {
        with_hmac_key(Some(TEST_KEY), || {
            ensure_bind_allowed("0.0.0.0:3012".parse().unwrap()).expect("keyed");
        });
    }

    #[test]
    fn ensure_bind_public_without_key_sad() {
        with_hmac_key(None, || {
            let addr: SocketAddr = "0.0.0.0:3012".parse().unwrap();
            let err = ensure_bind_allowed(addr).expect_err("must refuse");
            assert_eq!(err, BindPolicyError::NonLoopbackWithoutHmacKey { addr });
            assert!(!err.to_string().contains(TEST_KEY));
        });
    }

    #[test]
    fn ensure_bind_public_with_short_key_sad() {
        with_hmac_key(Some("dev-secret"), || {
            let addr: SocketAddr = "0.0.0.0:3012".parse().unwrap();
            let err = ensure_bind_allowed(addr).expect_err("short key must refuse");
            assert_eq!(err, BindPolicyError::NonLoopbackWithoutHmacKey { addr });
        });
    }
}
