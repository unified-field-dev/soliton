//! Typed errors for listen-address resolution and bind policy.

use std::fmt;
use std::net::SocketAddr;

/// Failure resolving `LEPTOS_SITE_ADDR` / `SITE_ADDR` into a [`SocketAddr`].
///
/// Display never includes the raw environment **value** (only the variable name).
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub enum ListenAddrError {
    /// Environment variable exists but is not valid Unicode.
    EnvNotUnicode {
        /// Environment variable name (`LEPTOS_SITE_ADDR` or `SITE_ADDR`).
        var: &'static str,
    },
    /// Environment variable is set but does not parse as a socket address.
    InvalidSocketAddr {
        /// Environment variable name (`LEPTOS_SITE_ADDR` or `SITE_ADDR`).
        var: &'static str,
    },
}

impl fmt::Display for ListenAddrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EnvNotUnicode { var } => {
                write!(f, "environment variable {var} is not valid Unicode")
            }
            Self::InvalidSocketAddr { var } => {
                write!(
                    f,
                    "environment variable {var} is not a valid socket address"
                )
            }
        }
    }
}

impl std::error::Error for ListenAddrError {}

/// Failure from [`crate::listener::ensure_bind_allowed`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub enum BindPolicyError {
    /// Non-loopback bind refused because `SUBSYSTEM_AUTH_HMAC_KEY` is unset or unusable.
    NonLoopbackWithoutHmacKey {
        /// Requested listen address (ops identity; not end-user PII).
        addr: SocketAddr,
    },
}

impl fmt::Display for BindPolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NonLoopbackWithoutHmacKey { addr } => write!(
                f,
                "refusing non-loopback bind {addr}: set SUBSYSTEM_AUTH_HMAC_KEY before exposing the process"
            ),
        }
    }
}

impl std::error::Error for BindPolicyError {}
