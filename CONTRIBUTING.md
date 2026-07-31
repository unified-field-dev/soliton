# Contributing to Soliton

Thank you for improving this project.

## Development setup

1. Clone [unified-field-dev/soliton](https://github.com/unified-field-dev/soliton)
2. Install Rust stable
3. From the repository root:

```bash
cargo fmt --all -- --check
cargo check --workspace
```

## Documentation

When you change public API behavior, configuration, or host wiring steps:

1. Update rustdoc on the affected symbols (workspace `missing_docs = "deny"`).
2. Public functions returning `Result` should document failure modes (`# Errors` preferred;
   `clippy::missing_errors_doc` is currently **allow** — ratchet toward documenting all public `Result`s).
3. Trait methods with meaningful semantics carry a `# Contract` subsection (invariants, caller
   obligations).
4. Prefer `# Examples` on host entry points (`resolve_listen_addr`, `serve`, middleware, HMAC).
5. Module-level `//!` docs should be offer-first: purpose, Concern→API table, short example.
   Do not add `# Owns` / `# Does not own` inventories unless a product-line distinction is required
   (Soliton has no such case today).
6. Keep the crate-root task table and [`soliton/examples/README.md`](soliton/examples/README.md)
   discoverable: `process_host` is the copy-paste host wire-up; `hmac_health_host` is auth smoke.
7. Run the verification block in [`docs/VERIFICATION.md`](docs/VERIFICATION.md) before opening a PR.

### Style

- Organize crate-root docs by **task**.
- Put full snippets on the item/module that owns the API; the crate root links without dumping.
- Update [`README.md`](README.md) when public API or host wiring steps change.

## Code of conduct

Participation is governed by [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md). Security reports: [`SECURITY.md`](SECURITY.md).

## Pull requests

- Prefer small, focused PRs.
- Include documentation updates with behavioral changes (see above).
