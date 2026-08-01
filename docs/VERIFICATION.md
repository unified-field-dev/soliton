# soliton verification

Re-run after code or doc changes. Thin Axum HTTP host helpers (listen/serve, health,
request extensions, optional subsystem HMAC, Tokio worker stack) — covered by
unit + integration tests below.

**Blast radius:** kit-local. **AWS campaign:** not required (no campaign inventory;
no new operator workflow). **Bench / EXPERIMENTS / PERFORMANCE_STUDY:** not required
(correctness-only; not a measured hot path). **IsolatedLab e2e:** not
required — `tests/*_contract.rs` + unit modules are the CI correctness gate.

## Environment

```bash
export CARGO_BUILD_JOBS=1
export CARGO_TARGET_DIR=target-soliton
```

## Unit + integration (CI)

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
```

## Docs (CI)

```bash
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features
```

## Supply chain (CI)

```bash
cargo deny check
```

### Examples (smoke)

Smokes are liveness / teaching checks. They do **not** replace the validating rows below.
Keys must be ≥32 bytes; examples do not auto-inject a secret.

```bash
SUBSYSTEM_AUTH_HMAC_KEY='soliton-test-hmac-key-32-bytes!!' cargo run -p soliton --example process_host
SUBSYSTEM_AUTH_HMAC_KEY='soliton-test-hmac-key-32-bytes!!' cargo run -p soliton --example hmac_health_host
```

| Artifact | Label |
|----------|-------|
| `process_host` | smoke |
| `hmac_health_host` (oneshot self-check) | smoke + light validation |

### TEST_MAP

| Behavior / invariant | Risk if untested | Unit tests | Integration tests | E2E / IsolatedLab | AWS campaign | Bench / perf study | Not testing |
|----------------------|------------------|------------|-------------------|-------------------|--------------|--------------------|-------------|
| `health_router` `GET /health` → 200 | Probes fail | `health::tests::health_route_returns_ok_happy_path` | Happy: `health_get_returns_ok_happy_path`. Sad: `unknown_path_is_not_found_sad` → 404 | Not required | Not required | Not required | Response body (status-only contract) |
| `resolve_listen_addr` loopback / all-interfaces default | Wrong bind interface | Happy: `resolve_loopback_default_happy_path`, `resolve_all_interfaces_default_happy_path` | Happy: `resolve_listen_addr_loopback_default_happy_path` | Not required | Not required | Not required | — |
| `resolve_listen_addr` env precedence | Dual-env wrong addr | Happy: `resolve_leptos_precedes_site_happy_path`, `resolve_site_addr_when_leptos_absent_happy_path`. Sad: `resolve_invalid_env_errors_without_echoing_value_sad`, `resolve_invalid_site_addr_when_leptos_absent_sad`, `resolve_invalid_leptos_does_not_fall_back_to_site_sad` (Display has var name only) | — | Not required | Not required | Not required | — |
| `ListenAddrError::EnvNotUnicode` | Wrong variant / silent fallback | Sad: `resolve_non_unicode_env_sad` (unix) | — | Not required | Not required | Not required | Non-unix platforms (cfg-gated) |
| `ensure_bind_allowed` | Public bind without M2M key / false deny | Happy: `ensure_bind_loopback_ok_happy_path`, `ensure_bind_ipv6_loopback_ok_happy_path`, `ensure_bind_public_with_key_ok_happy_path`. Sad: `ensure_bind_public_without_key_sad`, `ensure_bind_public_with_short_key_sad` → `BindPolicyError` | — | Not required | Not required | Not required | Key crypto validity (HMAC middleware) |
| `bind_tcp_with_policy` | Skip bind policy | — | Happy: `bind_tcp_with_policy_loopback_happy_path`, `bind_tcp_with_policy_public_with_key_happy_path`. Sad: `bind_tcp_with_policy_public_without_key_sad` | Not required | Not required | Not required | — |
| `bind_tcp` | Bind errors swallowed | — | Happy: `bind_tcp_loopback_ephemeral_happy_path`. Sad: `bind_tcp_address_in_use_sad` | Not required | Not required | Not required | — |
| `serve_with_graceful_shutdown` | Serve / shutdown regression | — | Happy: `serve_with_graceful_shutdown_health_then_stop_happy_path`. Sad: `serve_unknown_path_is_not_found_sad` (connect-retry poll) | Not required | Not required | Not required | Bare `serve()` (same accept loop; example listen smoke only); `ConnectInfo` wiring |
| `resolve_worker_stack_bytes` | Stack too small / ignored env | Happy/sad: `default_stack_when_env_missing_happy_path`, `parses_valid_env_override_happy_path`, `below_floor_and_invalid_fall_back_to_default` | Happy/sad: `worker_stack_default_happy_path`, `worker_stack_env_override_happy_path`, `worker_stack_invalid_or_below_floor_falls_back_sad` | Not required | Not required | Not required | `tokio_runtime::run` builder/`block_on` (example-only) |
| HMAC `/api` + `/api/*` enforce | Open subsystem API | Happy/sad crypto: `verify_accepts_matching_tag_*`, `header_pair_*`, `load_key_*`, `should_enforce_exact_api_and_handoff_roots` | Happy: `hmac_valid_api_request_happy_path`. Sad: `hmac_missing_or_bad_tag_returns_auth_errors_sad` (401/403), `hmac_unset_key_rejects_api_by_default_sad`, `hmac_short_key_rejects_api_sad`, `hmac_exact_api_root_enforced_sad`. Bypass: `hmac_bypasses_health_and_internal_happy_path` | Not required | Not required | Not required | Full product API behavior |
| HMAC `/__handoff_internal` + `/__handoff_internal/*` enforce | Open handoff routes | — | Happy: `hmac_handoff_valid_request_happy_path`. Sad: `hmac_handoff_missing_or_bad_tag_returns_auth_errors_sad`, `hmac_exact_handoff_root_enforced_sad` | Not required | Not required | Not required | Handoff product logic beyond path gate |
| HMAC body > 4 MiB → 400 | Limit / status drift | — | Sad: `hmac_oversized_body_returns_400_sad` | Not required | Not required | Not required | Exact Axum stream failure taxonomy beyond status |
| `attach_request_extensions` | Missing host state in handlers | Happy: `injects_extensions_before_handler_happy_path` | Happy: `attach_request_extensions_injects_before_handler_happy_path`. Sad: `attach_without_required_extension_rejects_extractor_sad` (middleware ran, injects nothing → 500) | Not required | Not required | Not required | Axum extractor internals |
| Tracing emit fields | Ops blind spots | — | — | Not required | Not required | Not required | Hosts own subscriber; best-effort observability |

## Notes

- Tests may `unwrap`/`expect`; production paths map bind/serve failures to
  `anyhow`/`ListenAddrError`/`BindPolicyError` and auth failures to HTTP status codes.
- Sad-path assertions check concrete status codes or typed error variants.
- `SUBSYSTEM_REQUIRE_AUTH_HMAC` is not consulted by the middleware (fail-closed is default).
- Env-mutating tests use process-wide mutexes; serve tests poll connect readiness instead of fixed sleeps.
