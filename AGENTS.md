# Rust Project — Agent Guide

## Framework: Abscissa

This project uses the [Abscissa](https://github.com/iqlusioninc/abscissa) application framework.

Key conventions:
- Application state lives in `Application` (implements `abscissa_core::Application`)
- Subcommands are structs implementing `abscissa_core::Runnable`
- Configuration is a struct implementing `serde::Deserialize` + `abscissa_core::Config`, loaded via `APP.config()`
- Errors use `abscissa_core::error::BoxError` or a project-local `Error` type wrapping it
- Entry point is `main.rs` calling `abscissa_core::boot()`
- Components are registered in `application.rs` via `register_components()`

When adding a subcommand:
1. Create `src/commands/<name>.rs` implementing `Runnable`
2. Add variant to `src/commands.rs` enum (derives `clap::Subcommand` via `abscissa_core`)
3. Register any new components in `Application::register_components` if needed

## Observability: observlib-rs

This project uses [observlib-rs](https://github.com/ForgottenBeast/observlib-rs) for observability configuration (tracing, metrics, logging).

- Initialize the observability stack early in your `Runnable::run()` or application boot, via `observlib::init(config)`
- Configuration is driven by the project's config struct — add an `observability: observlib::Config` field
- Do not use `tracing_subscriber::fmt::init()` or ad-hoc subscriber setup; always go through observlib
- Span and event instrumentation: use `#[tracing::instrument]` on public functions and `tracing::{info, warn, error, debug}` macros for log emission
- Metrics: use the handles exposed by observlib after init; do not create a separate registry

## Testing: QuickCheck

Property-based tests use [quickcheck](https://docs.rs/quickcheck).

Rules (see global policy for when property tests are required):
- Property functions return `bool` or `quickcheck::TestResult` — use `TestResult::discard()` to skip invalid inputs rather than panicking
- Generate custom types by implementing `quickcheck::Arbitrary`
- Put property tests in the same module as the code under test, in a `#[cfg(test)] mod props { ... }` block separate from `#[cfg(test)] mod tests { ... }`

Example:
```rust
#[cfg(test)]
mod props {
    use quickcheck_macros::quickcheck;

    #[quickcheck]
    fn round_trip(input: String) -> bool {
        decode(encode(&input)) == input
    }
}
```

## Cargo.toml requirements

Ensure these dependencies are present:

```toml
[dependencies]
abscissa_core = "0.8"
observlib = { git = "https://github.com/ForgottenBeast/observlib-rs" }
tracing = "0.1"
serde = { version = "1", features = ["derive"] }

[dev-dependencies]
quickcheck = "1"
quickcheck_macros = "1"
```

## Project layout

```
src/
├── application.rs      # Application struct, component registration
├── commands/
│   ├── mod.rs          # EntryPoint enum
│   └── <cmd>.rs        # One file per subcommand
├── config.rs           # Config struct (serde + abscissa Config)
├── error.rs            # Error / Result types
└── main.rs             # abscissa_core::boot() entry point
docs/
├── book.toml
├── research/           # ultraresearch session outputs (slug-named)
└── src/
    └── SUMMARY.md
```

## Build outputs

- `nix build .#default` — release binary
- `nix build .#doc` — mdBook from `docs/`
- `cargo doc` — Rust API docs

## See also

- Global rules: `~/.AGENTS.md`
- Abscissa docs: https://docs.rs/abscissa_core
- observlib-rs: https://github.com/ForgottenBeast/observlib-rs
