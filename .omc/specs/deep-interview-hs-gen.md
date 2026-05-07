# Deep Interview Spec: hs-gen

## Metadata
- Interview ID: di-hs-gen-20260507
- Rounds: 5
- Final Ambiguity Score: 15.6%
- Type: greenfield
- Generated: 2026-05-07
- Threshold: 0.20
- Initial Context Summarized: no
- Status: PASSED

## Clarity Breakdown
| Dimension | Score | Weight | Weighted |
|-----------|-------|--------|----------|
| Goal Clarity | 0.85 | 0.40 | 0.34 |
| Constraint Clarity | 0.88 | 0.30 | 0.264 |
| Success Criteria | 0.80 | 0.30 | 0.24 |
| **Total Clarity** | | | **0.844** |
| **Ambiguity** | | | **15.6%** |

## Goal

A Rust CLI tool (`hs-gen`) that deterministically generates Tor v3 and/or I2P (i2pd-compatible) hidden service keys from a password and a time-based epoch. The same password + epoch always produces the same service address; the address rotates automatically every `--validity` seconds. A daemon mode enables Elixir Port integration: the process owns its clock, auto-rotates at epoch boundaries, and accepts runtime commands over newline-delimited JSON on stdin/stdout.

## Constraints

### KDF construction (two-phase)
- **Phase 1 — password stretch:** `master_key = Argon2id(password, salt=STATIC_DOMAIN_SALT)`
  - `STATIC_DOMAIN_SALT` is a hardcoded domain-separation constant (e.g. `b"hs-gen-v1"` padded to Argon2 salt size)
  - Parameters: memory, iterations, parallelism TBD by implementer (Argon2id OWASP recommended minimums)
- **Phase 2 — per-epoch, per-network derivation:**
  - `epoch = floor(unix_timestamp / validity_seconds)`
  - `tor_seed  = HKDF-SHA512(master_key, info = epoch_le_u64 || b"tor-v3")`  → 32 bytes
  - `i2p_seed  = HKDF-SHA512(master_key, info = epoch_le_u64 || b"i2p-ed25519")` → 64 bytes

### Tor v3 key format
- Ed25519 expanded secret key (64 bytes) derived from `tor_seed` via the standard Ed25519 key-expand (SHA-512 of seed, clamped)
- Files written: `hs_ed25519_secret_key` (Tor binary format with header), `hs_ed25519_public_key`, `hostname` (base32 pubkey + checksum + version + `.onion`)
- Reference: Tor Prop 224 / rend-spec-v3.txt

### I2P key format (EdDSA-SHA512-Ed25519, type 7, i2pd-compatible)
- Signing key pair: Ed25519, derived from `i2p_seed[0..32]`
- Encryption key pair: X25519, derived from `i2p_seed[32..64]`
- Destination structure: 391-byte i2pd `.dat` format (PublicKey || SigningPublicKey || Certificate || PrivateKey || SigningPrivateKey)
- Files written: `destination.dat` (full private destination), `destination.b32.i2p` (base32 address file)

### CLI flags
| Flag | Type | Description |
|------|------|-------------|
| `--tor` | bool | Generate Tor v3 key |
| `--i2p` | bool | Generate I2P EdDSA-Ed25519 key |
| `--validity <seconds>` | u64 | Epoch length in seconds (default: 3600) |
| `--output-dir <path>` | path | Write service-directory files here |
| `--overwrite` | bool | Overwrite existing files in output-dir; otherwise create a new subdirectory per epoch |
| `--daemon` | bool | Run in daemon mode (owns clock, JSON protocol on stdio) |

At least one of `--tor` or `--i2p` must be specified. Without `--output-dir`, key material is printed to stdout.

### Password input
- Read from stdin until EOF (supports piping: `echo -n "pass" | hs-gen --tor`)
- UTF-8 bytes, no normalisation
- Zeroized from memory after Phase 1 completes

### Output directory layout (non-overwrite)
```
<output-dir>/
  <epoch>/
    tor/
      hs_ed25519_secret_key
      hs_ed25519_public_key
      hostname
    i2p/
      destination.dat
      destination.b32.i2p
```

With `--overwrite`: files written directly into `<output-dir>/tor/` and `<output-dir>/i2p/`.

### Daemon mode — JSON protocol (newline-delimited, Elixir `{:line, 4096}`)

**Startup sequence:**
1. Read password from stdin until a blank line or a `{"cmd":"password","value":"..."}` frame — TBD; simpler: read password before entering daemon loop (first line = password, subsequent lines = JSON commands).
2. Perform Argon2id stretch once; zeroize password bytes.
3. Emit startup event, generate initial keys, write output-dir, emit rotation event.

**Commands (stdin → daemon):**
```json
{"cmd": "set_validity", "seconds": 1800}
{"cmd": "status"}
{"cmd": "shutdown"}
```

**Events (daemon → stdout):**
```json
{"event": "started",  "epoch": 42, "validity": 3600}
{"event": "rotated",  "epoch": 43, "validity": 3600, "tor_onion": "abc...onion", "i2p_b32": "xyz...b32.i2p", "path": "/hs/43"}
{"event": "validity_changed", "new_validity": 1800, "effective_epoch": 44}
{"event": "status",   "epoch": 43, "validity": 3600, "next_rotation_in": 217}
{"event": "error",    "msg": "..."}
{"event": "shutdown"}
```

`set_validity` takes effect at the **next epoch boundary** (not mid-epoch). The daemon recomputes the next boundary using the new validity immediately after the current epoch ends.

### Target
- `aarch64-unknown-linux-musl` (static binary, from flake.nix)
- Single binary, no runtime dependencies

## Non-Goals
- Key caching / master key persistence across process restarts (re-derives each invocation)
- Network connectivity (does not start Tor/I2P processes)
- Key revocation or rotation history beyond what the filesystem holds
- DSA-SHA1 or any legacy I2P key type
- GUI or TUI
- Custom Argon2id parameters via CLI (hardcoded to safe defaults)

## Acceptance Criteria
- [ ] `echo -n "password" | hs-gen --tor --validity 3600` prints a stable `.onion` address for the current epoch, and a different one for the next epoch
- [ ] Same password + same epoch + same validity always produces the same `.onion` / `.b32.i2p` address (determinism)
- [ ] Different passwords produce different addresses (basic KDF correctness)
- [ ] `--output-dir ./out` writes the correct Tor directory structure; `tor` accepts the generated keys without error
- [ ] `--output-dir ./out` without `--overwrite` creates a new subdirectory per epoch; with `--overwrite` replaces in place
- [ ] `--daemon --output-dir ./out` emits `{"event":"rotated",...}` at each epoch boundary without manual intervention
- [ ] Daemon correctly applies `set_validity` at the next epoch boundary, not immediately
- [ ] Daemon password is zeroized from memory after Argon2id stretch
- [ ] i2pd accepts the generated `destination.dat` as a valid local destination (type 7)
- [ ] Binary builds for `aarch64-unknown-linux-musl` via `nix build`
- [ ] Property test: for any password, any validity in [60, 86400], and any epoch, derivation is deterministic

## Assumptions Exposed & Resolved
| Assumption | Challenge | Resolution |
|------------|-----------|------------|
| Output goes to stdout | "Is this a printer or a directory writer?" | Both: stdout default, `--output-dir` for filesystem layout |
| Simple one-phase KDF | "What if password is entered once and epochs are cheap?" | Two-phase: Argon2id stretch once → HKDF per epoch |
| Daemon needs a timer | "What if Elixir owns the clock?" | Daemon owns the clock; Elixir only sends `set_validity` commands |
| I2P = legacy DSA | "Which key type?" | EdDSA-SHA512-Ed25519 (type 7), i2pd-compatible |
| Overwrite is always desired | "What about key history?" | `--overwrite` flag; default creates per-epoch subdirectories |

## Technical Context
- Rust, `aarch64-unknown-linux-musl`, single static binary
- Nix flake already scaffolded with Fenix toolchain, cross-compilation target, mdBook docs
- Elixir OTP supervision tree will consume daemon as a Port: `Port.open({:spawn_executable, ...}, [:binary, {:line, 4096}])`
- Crates expected: `argon2`, `hkdf`/`sha2`, `ed25519-dalek`, `x25519-dalek`, `clap`, `serde_json`, `zeroize`

## Ontology (Key Entities)

| Entity | Type | Fields | Relationships |
|--------|------|--------|---------------|
| Password | core domain | bytes (UTF-8), zeroized after use | feeds into MasterKey |
| MasterKey | core domain | 32 bytes (Argon2id output), in-memory only | derived from Password; feeds into EpochKey |
| EpochKey | core domain | seed bytes, epoch number, network tag | derived from MasterKey + epoch + tag |
| TorServiceDir | supporting | hs_ed25519_secret_key, hs_ed25519_public_key, hostname | produced from EpochKey(tor) |
| I2PServiceDir | supporting | destination.dat, destination.b32.i2p | produced from EpochKey(i2p) |
| Daemon | core domain | validity, current_epoch, master_key, output_dir | owns clock; emits RotationEvent; accepts SetValidityCmd |
| RotationEvent | supporting | epoch, validity, tor_onion, i2p_b32, path | emitted by Daemon on epoch boundary |
| SetValidityCmd | supporting | new_validity_seconds | received by Daemon; effective at next boundary |

## Ontology Convergence
| Round | Entity Count | New | Changed | Stable | Stability Ratio |
|-------|-------------|-----|---------|--------|----------------|
| 1 | 5 | 5 | - | - | N/A |
| 2 | 6 | 1 | 0 | 5 | 83% |
| 3 | 7 | 1 | 0 | 6 | 86% |
| 4 | 8 | 1 | 0 | 7 | 87% |
| 5 | 8 | 0 | 0 | 8 | 100% |

## Interview Transcript
<details>
<summary>Full Q&A (5 rounds)</summary>

### Round 1
**Q:** What does the tool actually produce as output — and where does it go?
**A:** Both / configurable — stdout default, `--output-dir` flag for filesystem layout, `--overwrite` to replace vs. new subdir per key.
**Ambiguity:** 43% (Goal: 0.60, Constraints: 0.50, Criteria: 0.60)

### Round 2
**Q:** How should the time window be incorporated as KDF input?
**A:** Option B (two-phase): Argon2id for password stretch → master key; HKDF per epoch + network tag. Also: daemon mode for Elixir Port integration, --overwrite flag, per-epoch subdirectories.
**Ambiguity:** 33% (Goal: 0.70, Constraints: 0.65, Criteria: 0.60)

### Round 3
**Q:** What framing protocol should the daemon use on stdin/stdout?
**A:** Newline-delimited JSON (`{:line, 4096}` on the Elixir side).
**Ambiguity:** 28% (Goal: 0.75, Constraints: 0.75, Criteria: 0.65)

### Round 4
**Q:** What triggers key rotation in daemon mode?
**A:** Daemon owns the clock (auto-rotates at epoch boundary). Can receive a command to change epoch length (takes effect at next boundary).
**Ambiguity:** 21.5% (Goal: 0.80, Constraints: 0.80, Criteria: 0.75)

### Round 5
**Q:** Which I2P key type should be generated?
**A:** EdDSA-SHA512-Ed25519 (type 7), i2pd-compatible, Ed25519 signing + X25519 encryption.
**Ambiguity:** 15.6% (Goal: 0.85, Constraints: 0.88, Criteria: 0.80)

</details>
