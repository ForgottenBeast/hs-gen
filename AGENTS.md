# hs-gen — Agent Guide

## Overview

`hs-gen` is a Rust CLI tool that deterministically generates Tor v3 and I2P
hidden service keys from a password using a two-phase KDF. Keys rotate on a
configurable time window (epoch). A daemon mode supports Elixir Port integration.

## Module layout

```
src/
├── lib.rs          # Re-exports: kdf, tor, i2p, output, daemon
├── main.rs         # CLI entry point (clap derive)
├── kdf.rs          # Argon2id password stretch + HKDF epoch derivation
├── tor.rs          # Tor v3 Ed25519 key generation and file format
├── i2p.rs          # I2P type-7 EdDSA-Ed25519 + X25519 key generation
├── output.rs       # Stdout and filesystem output with atomic writes
└── daemon.rs       # Two-thread daemon with JSON protocol
docs/
├── book.toml
└── src/
    └── SUMMARY.md
```

## Cargo.toml dependencies

```toml
[dependencies]
argon2        = "0.5"
hkdf          = "0.12"
sha2          = "0.10"
sha3          = "0.10"
ed25519-dalek = { version = "2", features = ["hazmat", "zeroize"] }
x25519-dalek  = { version = "2", features = ["static_secrets", "zeroize"] }
clap          = { version = "4", features = ["derive"] }
serde         = { version = "1", features = ["derive"] }
serde_json    = "1"
zeroize       = { version = "1", features = ["derive"] }
data-encoding = "2"
ctrlc         = { version = "3", features = ["termination"] }

[dev-dependencies]
quickcheck       = "1"
quickcheck_macros = "1"
```

## CLI flags

| Flag | Default | Description |
|------|---------|-------------|
| `--tor` | false | Generate Tor v3 keys |
| `--i2p` | false | Generate I2P type-7 keys |
| `--validity` | 3600 | Epoch length in seconds (min 60) |
| `--output-dir` | — | Write service directory files |
| `--overwrite` | false | Overwrite in-place vs per-epoch subdirs |
| `--daemon` | false | Daemon mode (requires --output-dir) |

## KDF invariants (DO NOT CHANGE)

```
Phase 1: master_key = Argon2id(password, salt=b"hs-gen-v1\x00\x00\x00\x00\x00\x00\x00",
                                m=19456, t=2, p=1, out=32)
Phase 2: seed = HKDF-SHA512(IKM=master_key, salt=empty,
                             info=epoch_le_u64 || network_tag)
  Tor:  info = epoch_le_u64 || b"tor-v3"       -> 32 bytes
  I2P:  info = epoch_le_u64 || b"i2p-ed25519"  -> 64 bytes
Epoch = unix_timestamp_secs / validity_secs
```

## File format constants (DO NOT CHANGE)

### Tor v3
- HEADER_SECRET = b"== ed25519v1-secret: type0 ==\x00\x00\x00" (32 bytes)
- HEADER_PUBLIC = b"== ed25519v1-public: type0 ==\x00\x00\x00" (32 bytes)
- hs_ed25519_secret_key = 96 bytes (header + expanded key)
- hostname checksum uses SHA3-256, not SHA-256

### I2P type-7
- Certificate: [0x05, 0x00, 0x04, 0x00, 0x07, 0x00, 0x00]
- Full .dat = 679 bytes (391 public + 256 crypto_priv + 32 signing_priv)
- b32 = base32(SHA-256(391 bytes)) + ".b32.i2p"

## Daemon JSON protocol

Newline-delimited JSON, max 4096 bytes per line.
Elixir Port: `Port.open({:spawn_executable, ...}, [:binary, {:line, 4096}])`

Commands: set_validity, status, shutdown
Events: started, rotated, validity_changed, status, error, shutdown

## Testing conventions

- Property tests: `quickcheck` in `mod props` blocks
- Unit tests: `mod tests` blocks
- Integration tests: `tests/` directory

## Build

- `nix build` — aarch64-unknown-linux-musl static binary
- `cargo test` — all tests
