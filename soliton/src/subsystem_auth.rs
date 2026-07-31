//! Optional HMAC bearer for headless subsystem HTTP APIs.
//!
//! When [`load_hmac_key_material_from_env`] returns `Some`, [`axum_optional_subsystem_hmac`]
//! requires every `/api` / `/api/*` and `/__handoff_internal` / `/__handoff_internal/*` request
//! to include header `x-subsystem-auth` whose value is the lowercase hex encoding of
//! `HMAC-SHA256(key, method + "\n" + path_and_query + "\n" + body)`.
//!
//! [`subsystem_hmac_header_pair`] is used by remote HTTP clients to attach the same header.
//!
//! ## Production defaults
//!
//! Enforced paths require `SUBSYSTEM_AUTH_HMAC_KEY` (minimum 32 bytes of key material).
//! When the key is missing or too short, requests are rejected with **401** (fail closed).
//!
//! [`REQUIRE_SUBSYSTEM_HMAC_ENV`] / [`require_subsystem_hmac_from_env`] are available for
//! host-level policy checks; [`axum_optional_subsystem_hmac`] does **not** read them
//! (fail-closed is already the default when the key is missing).
//!
//! # Concern → API
//!
//! | Concern | API |
//! |---------|-----|
//! | Layer HMAC on an Axum router | [`axum_optional_subsystem_hmac`] |
//! | Client: build `x-subsystem-auth` header | [`subsystem_hmac_header_pair`] |
//! | Load key (`SUBSYSTEM_AUTH_HMAC_KEY`, optional `hex:`) | [`load_hmac_key_material_from_env`] |
//! | Header name constant | [`SUBSYSTEM_AUTH_HEADER_NAME`] |
//!
//! ## Path enforcement
//!
//! | Path | Behavior |
//! |------|----------|
//! | `/health`, `/internal/*` | Always pass through (no HMAC) |
//! | `/api`, `/api/*`, `/__handoff_internal`, `/__handoff_internal/*` | Enforced |
//! | Other paths | Pass through |
//!
//! # Examples
//!
//! Layer middleware:
//!
//! ```rust,no_run
//! use axum::Router;
//! use soliton::subsystem_auth::axum_optional_subsystem_hmac;
//!
//! let app: Router<()> = Router::new().layer(axum::middleware::from_fn(axum_optional_subsystem_hmac));
//! let _ = app;
//! ```
//!
//! Client signing (same key env as the server):
//!
//! ```rust,no_run
//! use soliton::subsystem_auth::subsystem_hmac_header_pair;
//!
//! # fn demo() {
//! if let Some((name, tag)) = subsystem_hmac_header_pair("GET", "/api/ping", b"") {
//!     // attach `name` / `tag` on the outbound request
//!     let _ = (name, tag);
//! }
//! # }
//! ```
//!
//! Rejected requests emit a [`tracing`] `warn` with HTTP status, a low-cardinality
//! `path_class` (`api` / `handoff_internal`), and a `reason` — never key material or bodies.
//! Hosts own the tracing subscriber.
//!
//! Runnable: `cargo run -p soliton --example process_host` (host) ·
//! `cargo run -p soliton --example hmac_health_host` (auth contract smoke)
//!
//! [`load_hmac_key_material_from_env`]: crate::subsystem_auth::load_hmac_key_material_from_env
//! [`axum_optional_subsystem_hmac`]: crate::subsystem_auth::axum_optional_subsystem_hmac
//! [`subsystem_hmac_header_pair`]: crate::subsystem_auth::subsystem_hmac_header_pair
//! [`REQUIRE_SUBSYSTEM_HMAC_ENV`]: crate::subsystem_auth::REQUIRE_SUBSYSTEM_HMAC_ENV
//! [`require_subsystem_hmac_from_env`]: crate::subsystem_auth::require_subsystem_hmac_from_env
//! [`SUBSYSTEM_AUTH_HEADER_NAME`]: crate::subsystem_auth::SUBSYSTEM_AUTH_HEADER_NAME

use axum::body::{to_bytes, Body};
use axum::extract::Request;
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::Response;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

/// Minimum accepted length of HMAC key material (bytes after UTF-8 / `hex:` decode).
pub const MIN_HMAC_KEY_LEN: usize = 32;

/// Request header clients send (`x-subsystem-auth`).
pub const SUBSYSTEM_AUTH_HEADER_NAME: &str = "x-subsystem-auth";

/// Environment variable name historically used for “require HMAC” signaling.
///
/// [`axum_optional_subsystem_hmac`] does not read this variable; fail-closed when the key
/// is missing is already the default. Prefer [`require_subsystem_hmac_from_env`] only for
/// host-level checks outside the middleware.
pub const REQUIRE_SUBSYSTEM_HMAC_ENV: &str = "SUBSYSTEM_REQUIRE_AUTH_HMAC";

/// Parse a require-HMAC flag string (`1` / `true` / `yes`, case-insensitive).
#[must_use]
pub fn parse_require_subsystem_hmac(value: &str) -> bool {
    let v = value.trim().to_ascii_lowercase();
    matches!(v.as_str(), "1" | "true" | "yes")
}

/// Read [`REQUIRE_SUBSYSTEM_HMAC_ENV`]: `1`, `true`, or `yes` (case-insensitive) ⇒ required.
///
/// Intended for host-level policy. [`axum_optional_subsystem_hmac`] does not call this;
/// missing `SUBSYSTEM_AUTH_HMAC_KEY` already fails closed.
#[must_use]
pub fn require_subsystem_hmac_from_env() -> bool {
    std::env::var(REQUIRE_SUBSYSTEM_HMAC_ENV).is_ok_and(|v| parse_require_subsystem_hmac(&v))
}

/// Reads `SUBSYSTEM_AUTH_HMAC_KEY`: UTF-8 key material, or `hex:` + hex bytes.
///
/// Returns [`None`] when the variable is unset, empty, `hex:` decoding fails, or the
/// decoded key is shorter than [`MIN_HMAC_KEY_LEN`].
pub fn load_hmac_key_material_from_env() -> Option<Vec<u8>> {
    let v = std::env::var("SUBSYSTEM_AUTH_HMAC_KEY").ok()?;
    let t = v.trim();
    if t.is_empty() {
        return None;
    }
    let key = if let Some(rest) = t.strip_prefix("hex:") {
        let rest = rest.trim();
        if rest.is_empty() {
            return None;
        }
        hex::decode(rest).ok()?
    } else {
        t.as_bytes().to_vec()
    };
    if key.len() < MIN_HMAC_KEY_LEN {
        return None;
    }
    Some(key)
}

fn hmac_hex(key: &[u8], method: &str, path_and_query: &str, body: &[u8]) -> Result<String, ()> {
    let mut mac = HmacSha256::new_from_slice(key).map_err(|_| ())?;
    mac.update(method.to_ascii_uppercase().as_bytes());
    mac.update(b"\n");
    mac.update(path_and_query.as_bytes());
    mac.update(b"\n");
    mac.update(body);
    Ok(hex::encode(mac.finalize().into_bytes()))
}

/// Returns `(header_name, hex_tag)` when `SUBSYSTEM_AUTH_HMAC_KEY` is configured.
///
/// `method` is uppercased before signing. `path_and_query` must match the request URI
/// (path plus optional `?query`). `body` is the raw request body bytes (empty for GET).
///
/// Returns [`None`] when the key is unset/unusable or MAC construction fails.
///
/// # Examples
///
/// ```rust,no_run
/// use soliton::subsystem_auth::subsystem_hmac_header_pair;
///
/// # fn demo() {
/// let pair = subsystem_hmac_header_pair("POST", "/api/ping", br#"{"ok":true}"#);
/// let _ = pair;
/// # }
/// ```
pub fn subsystem_hmac_header_pair(
    method: &str,
    path_and_query: &str,
    body: &[u8],
) -> Option<(&'static str, String)> {
    let key = load_hmac_key_material_from_env()?;
    let tag = hmac_hex(&key, method, path_and_query, body).ok()?;
    Some((SUBSYSTEM_AUTH_HEADER_NAME, tag))
}

fn verify_hex_mac(
    key: &[u8],
    method: &str,
    path_and_query: &str,
    body: &[u8],
    auth_hex: &str,
) -> bool {
    let Ok(expected_hex) = hmac_hex(key, method, path_and_query, body) else {
        return false;
    };
    let Ok(expected) = hex::decode(expected_hex.trim()) else {
        return false;
    };
    let Ok(provided) = hex::decode(auth_hex.trim()) else {
        return false;
    };
    // HMAC-SHA256 tags are always 32 bytes; reject other lengths before compare.
    if expected.len() != 32 || provided.len() != 32 {
        return false;
    }
    bool::from(expected.as_slice().ct_eq(provided.as_slice()))
}

fn should_enforce_path(path: &str) -> bool {
    path == "/api"
        || path.starts_with("/api/")
        || path == "/__handoff_internal"
        || path.starts_with("/__handoff_internal/")
}

/// Low-cardinality path class for telemetry (never the raw path).
fn path_class(path: &str) -> &'static str {
    if path == "/api" || path.starts_with("/api/") {
        "api"
    } else if path == "/__handoff_internal" || path.starts_with("/__handoff_internal/") {
        "handoff_internal"
    } else {
        "other"
    }
}

fn reject_hmac(status: StatusCode, path: &str, reason: &'static str) -> StatusCode {
    tracing::warn!(
        status = status.as_u16(),
        path_class = path_class(path),
        reason,
        "soliton subsystem hmac rejected"
    );
    status
}

/// Axum middleware: subsystem HMAC verification (fail-closed when key unset/too short).
///
/// Apply with `axum::middleware::from_fn(axum_optional_subsystem_hmac)`.
///
/// # Errors
///
/// Returns these [`StatusCode`] values as Axum middleware errors (they become HTTP responses):
///
/// - **401 Unauthorized** — enforced path and key missing/too short, or
///   `x-subsystem-auth` header missing/empty
/// - **403 Forbidden** — key present but tag does not match
/// - **400 Bad Request** — request body exceeds the 4 MiB read limit or cannot be buffered
///
/// Bypass (always `Ok`): `/health`, paths under `/internal/`, and paths outside
/// `/api` / `/api/*` and `/__handoff_internal` / `/__handoff_internal/*`.
///
/// Rejected requests emit a [`tracing`] warning (status, `path_class`, `reason`) at this
/// boundary only — never key material or request bodies.
///
/// # Examples
///
/// See the [module-level examples](crate::subsystem_auth).
pub async fn axum_optional_subsystem_hmac(
    req: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let path = req.uri().path().to_string();
    if path == "/health" || path.starts_with("/internal/") {
        return Ok(next.run(req).await);
    }
    if !should_enforce_path(&path) {
        return Ok(next.run(req).await);
    }

    let Some(key) = load_hmac_key_material_from_env() else {
        return Err(reject_hmac(StatusCode::UNAUTHORIZED, &path, "missing_key"));
    };

    let pq = req
        .uri()
        .path_and_query()
        .map_or_else(|| path.clone(), |p| p.as_str().to_string());
    let method = req.method().as_str().to_string();

    let auth_header = req
        .headers()
        .get(SUBSYSTEM_AUTH_HEADER_NAME)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    let (parts, body) = req.into_parts();
    let Ok(bytes) = to_bytes(body, 4 * 1024 * 1024).await else {
        return Err(reject_hmac(
            StatusCode::BAD_REQUEST,
            &path,
            "body_unreadable",
        ));
    };

    if auth_header.is_empty() {
        return Err(reject_hmac(
            StatusCode::UNAUTHORIZED,
            &path,
            "missing_header",
        ));
    }
    if !verify_hex_mac(&key, &method, &pq, &bytes, &auth_header) {
        return Err(reject_hmac(StatusCode::FORBIDDEN, &path, "bad_tag"));
    }

    let req = Request::from_parts(parts, Body::from(bytes));
    Ok(next.run(req).await)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static HMAC_ENV_LOCK: Mutex<()> = Mutex::new(());

    /// 32-byte UTF-8 test key (meets [`MIN_HMAC_KEY_LEN`]).
    const TEST_KEY: &str = "soliton-test-hmac-key-32-bytes!!";

    fn with_hmac_env<R>(value: Option<&str>, f: impl FnOnce() -> R) -> R {
        let _g = HMAC_ENV_LOCK.lock().unwrap();
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

    fn with_require_env<R>(value: Option<&str>, f: impl FnOnce() -> R) -> R {
        let _g = HMAC_ENV_LOCK.lock().unwrap();
        let prev = std::env::var(REQUIRE_SUBSYSTEM_HMAC_ENV).ok();
        match value {
            Some(v) => std::env::set_var(REQUIRE_SUBSYSTEM_HMAC_ENV, v),
            None => std::env::remove_var(REQUIRE_SUBSYSTEM_HMAC_ENV),
        }
        let out = f();
        match prev {
            Some(v) => std::env::set_var(REQUIRE_SUBSYSTEM_HMAC_ENV, v),
            None => std::env::remove_var(REQUIRE_SUBSYSTEM_HMAC_ENV),
        }
        out
    }

    #[test]
    fn parse_require_subsystem_hmac_truthy_and_falsy() {
        assert!(parse_require_subsystem_hmac("1"));
        assert!(parse_require_subsystem_hmac("true"));
        assert!(parse_require_subsystem_hmac("YES"));
        assert!(!parse_require_subsystem_hmac(""));
        assert!(!parse_require_subsystem_hmac("0"));
        assert!(!parse_require_subsystem_hmac("no"));
    }

    #[test]
    fn require_from_env_defaults_false() {
        with_require_env(None, || {
            assert!(!require_subsystem_hmac_from_env());
        });
        with_require_env(Some("1"), || {
            assert!(require_subsystem_hmac_from_env());
        });
    }

    #[test]
    fn load_key_none_when_unset_or_empty_sad() {
        with_hmac_env(None, || {
            assert!(load_hmac_key_material_from_env().is_none());
        });
        with_hmac_env(Some("   "), || {
            assert!(load_hmac_key_material_from_env().is_none());
        });
        with_hmac_env(Some("hex:"), || {
            assert!(load_hmac_key_material_from_env().is_none());
        });
    }

    #[test]
    fn load_key_rejects_short_utf8_sad() {
        with_hmac_env(Some("dev-secret"), || {
            assert!(load_hmac_key_material_from_env().is_none());
        });
    }

    #[test]
    fn load_key_utf8_and_hex_happy_path() {
        assert_eq!(TEST_KEY.len(), MIN_HMAC_KEY_LEN);
        with_hmac_env(Some(TEST_KEY), || {
            assert_eq!(
                load_hmac_key_material_from_env().as_deref(),
                Some(TEST_KEY.as_bytes())
            );
        });
        // 32 bytes as hex (64 hex chars)
        let hex_key = format!("hex:{}", "ab".repeat(32));
        with_hmac_env(Some(&hex_key), || {
            let loaded = load_hmac_key_material_from_env().expect("hex key");
            assert_eq!(loaded.len(), 32);
            assert_eq!(loaded, vec![0xab; 32]);
        });
        with_hmac_env(Some("hex:zz"), || {
            assert!(load_hmac_key_material_from_env().is_none());
        });
        with_hmac_env(Some("hex:deadbeef"), || {
            assert!(load_hmac_key_material_from_env().is_none());
        });
    }

    #[test]
    fn header_pair_none_without_key_sad() {
        with_hmac_env(None, || {
            assert!(subsystem_hmac_header_pair("GET", "/api/x", b"").is_none());
        });
    }

    #[test]
    fn header_pair_stable_for_same_inputs_happy_path() {
        with_hmac_env(Some(TEST_KEY), || {
            let a = subsystem_hmac_header_pair("POST", "/api/jobs?x=1", b"body").unwrap();
            let b = subsystem_hmac_header_pair("POST", "/api/jobs?x=1", b"body").unwrap();
            assert_eq!(a.0, SUBSYSTEM_AUTH_HEADER_NAME);
            assert_eq!(a.1, b.1);
            let c = subsystem_hmac_header_pair("POST", "/api/jobs?x=1", b"other").unwrap();
            assert_ne!(a.1, c.1);
        });
    }

    #[test]
    fn verify_accepts_matching_tag_rejects_mismatch_happy_and_sad() {
        let key = TEST_KEY.as_bytes();
        let tag = hmac_hex(key, "GET", "/api/x", b"{}").unwrap();
        assert!(verify_hex_mac(key, "GET", "/api/x", b"{}", &tag));
        assert!(!verify_hex_mac(key, "GET", "/api/x", b"{}", "00"));
        assert!(!verify_hex_mac(key, "POST", "/api/x", b"{}", &tag));
        assert!(!verify_hex_mac(key, "GET", "/api/x", b"{}", &tag[..32]));
    }

    #[test]
    fn should_enforce_exact_api_and_handoff_roots() {
        assert!(should_enforce_path("/api"));
        assert!(should_enforce_path("/api/ping"));
        assert!(should_enforce_path("/__handoff_internal"));
        assert!(should_enforce_path("/__handoff_internal/x"));
        assert!(!should_enforce_path("/health"));
        assert!(!should_enforce_path("/internal/ok"));
        assert!(!should_enforce_path("/public"));
        assert!(!should_enforce_path("/API/ping"));
    }
}
