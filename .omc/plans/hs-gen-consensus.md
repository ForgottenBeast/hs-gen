# hs-gen — Consensus Implementation Plan

> **Status:** APPROVED (Planner + Architect + Critic — 1 iteration)
> **Spec:** `.omc/specs/deep-interview-hs-gen.md`
> **Do not begin implementation until the user says so.**

---

## RALPLAN-DR Summary

### Principles
1. **Determinism above all** — same (password, epoch, validity, network) always produces identical output, byte-for-byte
2. **Minimal surface area** — single static binary, no framework, no async runtime; only the listed crates
3. **Zeroize-by-default** — every secret buffer implements `Zeroize`/`ZeroizeOnDrop`; dropped before daemon loop
4. **Format fidelity** — Tor and I2P output bytes must match what `tor` and `i2pd` expect, verified against their source
5. **Elixir Port compatibility** — daemon lines always < 4096 bytes; stdout flushed after every write; stdin EOF = graceful shutdown

### Decision Drivers
1. Correctness of cryptographic output formats (a single wrong byte breaks tool interoperability)
2. Cross-compilation to `aarch64-unknown-linux-musl` (crate selection must avoid C dependencies)
3. Daemon complexity (two event sources only — stdin commands and epoch timer)

### Viable Options

#### A (CHOSEN): Synchronous daemon with `std::thread` + `mpsc::recv_timeout`
- **Pros:** No async runtime; minimal binary; no musl cross-compilation friction; maps naturally to two-source select
- **Cons:** Harder to unit-test timing behaviour (requires subprocess integration tests); migration to mio needed if a third event source ever appears

#### B (REJECTED): Tokio async runtime
- **Invalidation:** `select!` ergonomics do not justify +2 MB binary and musl linking friction for a two-source daemon. Argon2id is CPU-bound and would need `spawn_blocking`. Clean migration path (mio) exists if requirements grow.

#### C (REJECTED): Abscissa application framework
- **Invalidation:** The tool has zero subcommands and no config file. Abscissa adds ceremony without benefit. `clap` derive is the right tool.

---

## Requirements Summary

| ID | Requirement |
|----|-------------|
| R1 | Deterministic: same (password, epoch, validity) → same address |
| R2 | `--tor` generates Tor v3 hidden service keys in Tor-compatible binary format |
| R3 | `--i2p` generates I2P EdDSA-Ed25519 type-7 destination in i2pd-compatible format |
| R4 | `--output-dir` writes service directories; without it, print to stdout |
| R5 | `--overwrite` replaces in-place; default creates `<epoch>/tor/` and `<epoch>/i2p/` subdirs |
| R6 | `--daemon` owns the clock; auto-rotates at epoch boundary; accepts `set_validity` at runtime |
| R7 | Daemon communicates via newline-delimited JSON; all lines < 4096 bytes |
| R8 | `set_validity` takes effect at the NEXT epoch boundary |
| R9 | Password bytes zeroized after Argon2id stretch; never stored on disk |
| R10 | Binary builds for `aarch64-unknown-linux-musl` via `nix build` |

---

## Acceptance Criteria

- [ ] `echo -n "password" | hs-gen --tor --validity 3600` prints a stable `.onion` address for the current epoch
- [ ] Same password + same epoch + same validity produces identical `.onion` / `.b32.i2p` across two invocations
- [ ] Different passwords produce different addresses (basic KDF correctness)
- [ ] `--output-dir ./out --tor` creates `out/tor/{hs_ed25519_secret_key,hs_ed25519_public_key,hostname}` with permissions 0600
- [ ] `tor` accepts the generated `hs_ed25519_secret_key` + `hostname` and binds the `.onion` (manual verification step)
- [ ] Non-overwrite mode creates `out/<epoch>/tor/` and `out/<epoch>/i2p/` subdirs
- [ ] Overwrite mode writes to `out/tor/` and `out/i2p/` directly, replacing existing files
- [ ] `--daemon --output-dir ./out` emits `{"event":"rotated",...}` at each epoch boundary without manual intervention
- [ ] Daemon `set_validity` command takes effect at the next epoch boundary, not immediately
- [ ] Password bytes are zeroized before daemon enters the JSON command loop
- [ ] i2pd accepts the generated `destination.dat` as a valid type-7 local destination (manual verification)
- [ ] `nix build` produces an `aarch64-unknown-linux-musl` static binary (verify with `file result/bin/hs-gen`)
- [ ] Property test: for any password bytes, any `validity` in `[60, 86400]`, and any `epoch`, derivation is deterministic
- [ ] All daemon event JSON lines are < 4096 bytes (unit test with maximum-length addresses)
- [ ] `cargo test` passes on all unit, property, and integration tests

---

## Cryptographic Constants (locked — do not deviate)

### Argon2id parameters
```
m_cost = 19456       (19 MiB, OWASP minimum)
t_cost = 2           (2 iterations)
p_cost = 1           (1 thread)
output = 32 bytes
salt   = b"hs-gen-v1\x00\x00\x00\x00\x00\x00\x00"  // exactly 16 bytes
```

### HKDF-SHA512
```
IKM    = master_key (32 bytes from Argon2id)
salt   = b""  (empty — Argon2id output is already high-entropy; per RFC 5869 defaults to HashLen zeros)
info   = epoch.to_le_bytes() || network_tag
output lengths:
  Tor  → 32 bytes  (info = epoch_le_u64 || b"tor-v3")
  I2P  → 64 bytes  (info = epoch_le_u64 || b"i2p-ed25519")
```

### Epoch
```
epoch = unix_timestamp_secs / validity_secs   (integer division, no rounding)
```

### Tor v3 key files
```
// hs_ed25519_secret_key — 96 bytes exactly
HEADER_SECRET = b"== ed25519v1-secret: type0 ==\x00\x00\x00"  // 32 bytes
FILE = HEADER_SECRET || expanded_secret_key  // 32 + 64 = 96 bytes

expanded_secret_key (64 bytes):
  h = SHA-512(tor_seed_32)
  h[0]  &= 248
  h[31] &= 63
  h[31] |= 64
  // lower 32 bytes = clamped scalar; upper 32 bytes = nonce prefix

// hs_ed25519_public_key — 64 bytes exactly
HEADER_PUBLIC = b"== ed25519v1-public: type0 ==\x00\x00\x00"  // 32 bytes
FILE = HEADER_PUBLIC || ed25519_public_key  // 32 + 32 = 64 bytes

// hostname
checksum = SHA3-256(b".onion checksum" || ed25519_public_key[32] || b"\x03")[0..2]
onion    = base32(ed25519_public_key[32] || checksum[2] || b"\x03") + ".onion"
// base32: RFC 4648, lowercase, no padding
// total: 56 base32 chars + ".onion" = 62 chars
```

### I2P type-7 destination (i2pd .dat format)

**Crypto type decision (resolved by Architect):** Use `crypto_type = 0` (ElGamal placeholder) with a zeroed 256-byte PublicKey field. The b32 address is `SHA-256(public_destination)` regardless of encryption key content, and i2pd accepts type-7 destinations for server-side use without validating ElGamal key material. X25519 is still derived from `i2p_seed[32..64]` in case future versions require it, but the `.dat` file uses the zeroed ElGamal field for the crypto public key. If i2pd validation of the crypto key is discovered during integration testing, revisit to crypto_type=4.

```
// Public destination — 391 bytes
crypto_pubkey     : [u8; 256]  = [0u8; 256]          // zeroed ElGamal placeholder
signing_pubkey    : [u8; 128]  = ed25519_pubkey || [0; 96]  // Ed25519 pubkey zero-padded to 128
certificate       : [u8; 7]    = [
    0x05,           // type = KEY_CERT
    0x00, 0x04,     // length = 4 (big-endian u16)
    0x00, 0x07,     // signing_type = 7 EdDSA-SHA512-Ed25519 (big-endian u16)
    0x00, 0x00,     // crypto_type = 0 ElGamal (big-endian u16)
]
// Total public = 256 + 128 + 7 = 391 bytes ✓

// Private keys appended
crypto_privkey    : [u8; 256]  = x25519_privkey || [0; 224]  // X25519 key zero-padded to 256
signing_privkey   : [u8; 32]   = ed25519_seed  // 32-byte Ed25519 seed (NOT expanded key)

// b32 address
b32 = base32(SHA-256(public_destination_391_bytes)) + ".b32.i2p"
// base32: RFC 4648, lowercase, no padding
```

**CRITICAL:** Verify this exact layout against i2pd source `libi2pd/Identity.cpp` (`PrivateKeys::FromBuffer`) before finalising. The layout above is derived from reading i2pd documentation and source references; the integration test (i2pd accepts destination.dat) is the definitive acceptance gate.

---

## Implementation Phases

### Phase 1: Project Scaffolding

**Files:** `Cargo.toml`, `src/lib.rs`, `src/main.rs`, `AGENTS.md`, `flake.nix`

**Cargo.toml dependencies:**
```toml
[dependencies]
argon2      = "0.5"
hkdf        = "0.12"
sha2        = "0.10"
sha3        = "0.10"
ed25519-dalek = { version = "2", features = ["hazmat", "zeroize"] }
x25519-dalek  = { version = "2", features = ["static_secrets", "zeroize"] }
clap        = { version = "4", features = ["derive"] }
serde       = { version = "1", features = ["derive"] }
serde_json  = "1"
zeroize     = { version = "1", features = ["derive"] }
data-encoding = "2"   # base32 and base64

[dev-dependencies]
quickcheck       = "1"
quickcheck_macros = "1"
```

**Module layout** (`src/lib.rs` re-exports):
```
pub mod kdf;
pub mod tor;
pub mod i2p;
pub mod output;
pub mod daemon;
```

**AGENTS.md changes:**
- Remove all Abscissa and observlib-rs references
- Remove OpenTelemetry requirement (this is a CLI leaf tool consumed as an Elixir Port; telemetry belongs in the Elixir supervision tree)
- Document flat module structure and actual crate list
- Note: OpenBao/Dex in devShell are inherited from template; retain but document they are not used by hs-gen itself

**Acceptance criteria:**
- `cargo check` passes
- Module structure compiles
- AGENTS.md accurately reflects the project

---

### Phase 2: Core KDF (`src/kdf.rs`)

```rust
// Public API (abbreviated)
pub struct MasterKey(Zeroizing<[u8; 32]>);
pub fn derive_master_key(password: &[u8]) -> Result<MasterKey, Error>;

pub enum NetworkTag { Tor, I2p }
pub fn derive_epoch_seed(
    master: &MasterKey,
    epoch: u64,
    network: NetworkTag,
    len: usize,        // 32 for Tor, 64 for I2P
) -> Zeroizing<Vec<u8>>;

pub fn current_epoch(validity_secs: u64) -> u64;
```

**Invariants:**
- `MasterKey` is `Zeroizing`; password bytes are zeroized in the caller after this function returns
- `derive_epoch_seed` is pure — no side effects, same inputs → same output
- Argon2id parameters: exactly as listed in Constants section above

**Tests:**
- Golden test: `derive_master_key(b"test")` → known 32-byte hex (generate offline, pin in test)
- Golden test: `derive_epoch_seed(master, epoch=42, Tor, 32)` → known 32-byte hex
- Property: `derive_epoch_seed` is idempotent (run twice, assert equal)
- Property: different epochs → different seeds
- Property: `Tor` tag ≠ `I2p` tag for same epoch

---

### Phase 3: Tor v3 Key Generation (`src/tor.rs`)

```rust
pub struct TorKeys {
    pub secret_key_file: [u8; 96],    // HEADER + expanded_secret_key
    pub public_key_file: [u8; 64],    // HEADER + ed25519_pubkey
    pub hostname: String,             // 62 chars: 56 base32 + ".onion"
}
impl Zeroize for TorKeys { ... }

pub fn generate_tor_keys(seed: &[u8; 32]) -> TorKeys;
```

**Key constants** (from `src/tor.rs`):
```rust
const HEADER_SECRET: &[u8; 32] = b"== ed25519v1-secret: type0 ==\x00\x00\x00";
const HEADER_PUBLIC: &[u8; 32] = b"== ed25519v1-public: type0 ==\x00\x00\x00";
const ONION_CHECKSUM_PREFIX: &[u8] = b".onion checksum";
const ONION_VERSION: u8 = 0x03;
```

**Key-expand procedure:**
```
h = SHA-512(seed)                    // 64 bytes
h[0]  &= 248                         // clear lower 3 bits
h[31] &= 63                          // clear upper 2 bits
h[31] |= 64                          // set second-highest bit
expanded_secret = h[0..32] || h[32..64]
```

**Ed25519 public key:** derive via `ed25519_dalek::hazmat::ExpandedSecretKey::from_bytes(&h).verifying_key().to_bytes()`

**Tests:**
- Golden: known seed → known `.onion` address (generate reference from Python `cryptography` + manual spec calc)
- Unit: secret key file is exactly 96 bytes, first 32 bytes match `HEADER_SECRET`
- Unit: public key file is exactly 64 bytes, first 32 bytes match `HEADER_PUBLIC`
- Unit: hostname is exactly 62 characters, ends with `.onion`
- Property: different seeds → different hostnames
- Unit: SHA3-256 (NOT SHA-256) used for checksum — verify with known vector

---

### Phase 4: I2P Key Generation (`src/i2p.rs`)

```rust
pub struct I2pKeys {
    pub destination_dat: Vec<u8>,  // 391 + 256 + 32 = 679 bytes
    pub b32_address: String,       // base32(sha256(391-byte public)) + ".b32.i2p"
}

pub fn generate_i2p_keys(seed: &[u8; 64]) -> I2pKeys;
```

**Build steps:**
1. Ed25519 keypair from `seed[0..32]`
2. X25519 private key from `seed[32..64]`; compute X25519 public key
3. Assemble `destination_dat` per the byte layout in Constants section

**Verification gate (CRITICAL — do before Phase 5):**
Run i2pd's `keygen` tool or parse a known-good `.dat` file and compare field offsets byte-for-byte against the layout above. Only proceed if the layout is confirmed.

**Tests:**
- Unit: `destination_dat` is exactly 679 bytes
- Unit: bytes `[512..519]` match the certificate constant `[0x05, 0x00, 0x04, 0x00, 0x07, 0x00, 0x00]`
- Unit: deterministic — same seed → same b32 address
- Property: different seeds → different b32 addresses
- Integration (deferred to Phase 8): i2pd accepts the `.dat` file

---

### Phase 5: Output Module (`src/output.rs`)

```rust
pub enum OutputTarget {
    Stdout,
    Directory { path: PathBuf, overwrite: bool },
}

pub fn write_tor(keys: &TorKeys, epoch: u64, target: &OutputTarget) -> Result<()>;
pub fn write_i2p(keys: &I2pKeys, epoch: u64, target: &OutputTarget) -> Result<()>;
```

**Directory paths:**
- `overwrite=true`: `<path>/tor/{hs_ed25519_secret_key, hs_ed25519_public_key, hostname}`, `<path>/i2p/{destination.dat, destination.b32.i2p}`
- `overwrite=false`: `<path>/<epoch>/tor/...`, `<path>/<epoch>/i2p/...`

**File permissions:** 0600 for all key files (use `std::fs::set_permissions`)

**Atomic writes:** Write to `<file>.tmp`, then `rename` to `<file>`. Avoids partial key files on crash.

**Stdout format:**
```
=== TOR ===
onion: <hostname>
secret_key (base64): <base64(secret_key_file[32..])>   // key bytes only, not header
public_key (base64): <base64(public_key_file[32..])>

=== I2P ===
b32: <b32_address>
destination (base64): <base64(destination_dat[0..391])>  // public part only
```

**Tests:**
- Unit: directory structure matches spec for both overwrite modes
- Unit: file permissions are 0600
- Unit: stdout output is human-readable and contains the address on line 2 (for scripting)
- Unit: atomic write — simulated crash during `.tmp` file write leaves no corrupted key file

---

### Phase 6: CLI Parsing and One-Shot Mode (`src/main.rs`)

```rust
#[derive(Parser)]
struct Args {
    #[arg(long)] tor: bool,
    #[arg(long)] i2p: bool,
    #[arg(long, default_value = "3600")] validity: u64,
    #[arg(long)] output_dir: Option<PathBuf>,
    #[arg(long)] overwrite: bool,
    #[arg(long)] daemon: bool,
}
```

**Validation (before reading password):**
- At least one of `--tor`/`--i2p` must be set → clap `required_unless_present_any` or manual check → exit 1 with message
- `--validity` must be >= 60 → manual check
- `--daemon` requires `--output-dir` → manual check

**One-shot flow:**
1. Read password from stdin until EOF (`std::io::stdin().read_to_end()`)
2. Call `derive_master_key(password_bytes)` — returns `MasterKey`
3. Zeroize `password_bytes`
4. Compute `epoch = current_epoch(args.validity)`
5. If `--tor`: `derive_epoch_seed(master, epoch, Tor, 32)` → `generate_tor_keys` → `write_tor`
6. If `--i2p`: `derive_epoch_seed(master, epoch, I2p, 64)` → `generate_i2p_keys` → `write_i2p`
7. Exit 0; on any error print to stderr, exit 1

**Daemon flow:**
1. Read password from stdin until first `\n` (`stdin.read_line(&mut buf)`) — NOT until EOF
2. Trim trailing newline from password
3. `derive_master_key(password_bytes)` → zeroize password
4. Call `daemon::run(master_key, &args)` — does not return until shutdown

**Tests:**
- Unit: `--tor` and `--i2p` both absent → exit code 1
- Unit: `--daemon` without `--output-dir` → exit code 1
- Unit: `--validity 59` → exit code 1
- Integration: pipe password, verify address printed to stdout

---

### Phase 7: Daemon Mode (`src/daemon.rs`)

**Architecture:** Two threads, one `mpsc` channel.

```
┌─────────────────┐  Command  ┌──────────────────────────────────────┐
│  stdin reader   │ ────────► │  main loop                           │
│  (thread)       │           │  recv_timeout(time_to_next_epoch)    │
│                 │           │  ├── timeout:  rotate keys           │
│                 │           │  ├── Command::SetValidity: store     │
│                 │           │  ├── Command::Status: emit status    │
│                 │           │  └── Command::Shutdown / EOF: exit   │
└─────────────────┘           └──────────────────────────────────────┘
```

**`run` function:**
```rust
pub fn run(master_key: MasterKey, args: &Args) -> Result<()> {
    let (tx, rx) = mpsc::channel::<Command>();

    // spawn stdin reader thread
    thread::spawn(move || {
        let stdin = io::stdin();
        for line in stdin.lock().lines() {
            match line {
                Ok(l) if !l.is_empty() => {
                    if let Ok(cmd) = serde_json::from_str(&l) { let _ = tx.send(cmd); }
                    else { emit_error("invalid command JSON"); }
                }
                _ => break,  // EOF or error — sender drops, main loop exits
            }
        }
    });

    let mut validity = args.validity;
    let mut pending_validity: Option<u64> = None;

    // Initial rotation
    let epoch = current_epoch(validity);
    let keys = derive_and_write(&master_key, epoch, validity, args)?;
    emit_started(epoch, validity);
    emit_rotated(epoch, validity, &keys, args);

    loop {
        let next_epoch_start = (epoch + 1) * validity;
        let now = unix_now();
        let sleep = Duration::from_secs(next_epoch_start.saturating_sub(now));

        match rx.recv_timeout(sleep) {
            Err(RecvTimeoutError::Timeout) => {
                // Recheck actual time (recv_timeout may wake slightly early)
                let now = unix_now();
                let new_epoch = now / validity;
                if new_epoch > current_epoch_tracked {
                    if let Some(pv) = pending_validity.take() { validity = pv; }
                    let keys = derive_and_write(&master_key, new_epoch, validity, args)?;
                    emit_rotated(new_epoch, validity, &keys, args);
                    current_epoch_tracked = new_epoch;
                }
            }
            Ok(Command::SetValidity { seconds }) => {
                pending_validity = Some(seconds);
                let effective_epoch = current_epoch_tracked + 1;
                emit_validity_changed(seconds, effective_epoch);
            }
            Ok(Command::Status) => emit_status(current_epoch_tracked, validity, next_epoch_start - unix_now()),
            Ok(Command::Shutdown) | Err(RecvTimeoutError::Disconnected) => {
                emit_shutdown();
                break;
            }
        }
    }
    Ok(())
}
```

**Output discipline:**
- All events: `writeln!(io::stdout().lock(), "{}", json)?; io::stdout().flush()?;`
- Every event must fit on one line < 4096 bytes (longest: rotated event with full addresses)
- Verify max line length in unit test

**Signal handling:**
- SIGTERM: Elixir Port sends SIGTERM on `Port.close/1`. Install a `ctrlc` handler (or use `signal-hook` crate) that sends `Command::Shutdown` via the tx channel, triggering graceful zeroization before exit.
- Add `ctrlc` or `signal-hook` to Cargo.toml dependencies.
- SIGPIPE: default behaviour (process exits); stdout being closed causes `writeln!` to error → propagate and exit cleanly.

**Tests:**
- Integration: spawn daemon with `--validity 2` (short epoch), read password line, wait for `rotated` event
- Integration: send `{"cmd":"status"}`, verify response contains `epoch` and `next_rotation_in`
- Integration: send `{"cmd":"set_validity","seconds":120}`, verify `validity_changed` event, wait for next rotation with new validity
- Integration: close stdin pipe, verify daemon emits `shutdown` and exits with code 0
- Unit: max event line length < 4096 bytes

---

### Phase 8: Tests (`tests/integration.rs`)

**Property tests (quickcheck) — per module:**
- KDF determinism: `for all (password: Vec<u8>, epoch: u64, validity: u64 in 60..=86400)` — two derivations produce identical bytes
- Uniqueness: `for all (p1: Vec<u8>, p2: Vec<u8>) where p1 != p2` — derived Tor addresses differ
- Epoch monotonicity: `epoch_n` and `epoch_n+1` produce different seeds

**Integration tests:**
```
tests/integration.rs:
  test_one_shot_tor_stdout()
  test_one_shot_i2p_stdout()
  test_one_shot_output_dir_no_overwrite()
  test_one_shot_output_dir_overwrite()
  test_determinism_across_invocations()
  test_daemon_initial_rotation()      // validity=2s, read rotated event
  test_daemon_set_validity()          // change validity mid-epoch
  test_daemon_status()                // status command + response
  test_daemon_shutdown_on_stdin_eof() // close stdin, verify exit 0
```

---

### Phase 9: Nix Build Integration (`flake.nix`)

**Changes required:**

1. `pname = "hs-gen"` (currently `"package"`)
2. Remove `cmake` from `nativeBuildInputs` (all crates are pure Rust — no C deps)
3. **Fix cross-compilation** (currently non-functional for aarch64-musl):
   ```nix
   # In buildRustPackage or rustPlatform.buildRustPackage:
   CARGO_BUILD_TARGET = target;  # "aarch64-unknown-linux-musl"
   CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER =
     "${pkgsCross.aarch64-multiplatform.stdenv.cc}/bin/${pkgsCross.aarch64-multiplatform.stdenv.cc.targetPrefix}cc";
   ```
   Or use `pkgsCross.aarch64-multiplatform.pkgsStatic.rustPlatform.buildRustPackage` for a native musl build.
4. Commit `Cargo.lock` (required by `cargoLock.lockFile`)
5. Verify `nix build .#doc` still works after pname change

**Acceptance:**
- `nix build` succeeds
- `file result/bin/hs-gen` shows `ELF 64-bit LSB executable, ARM aarch64, statically linked` (on x86_64 host cross-compiling) or appropriate native output
- `nix build .#doc` produces guide + rustdoc

---

## Risks and Mitigations

| Risk | Severity | Mitigation |
|------|----------|------------|
| **I2P .dat byte layout wrong** | HIGH | Verify byte-for-byte against i2pd `libi2pd/Identity.cpp` `PrivateKeys::FromBuffer` BEFORE Phase 5. Unit test checks certificate bytes at offsets [512..519]. Integration test (i2pd accepts file) is the final gate. |
| **crypto_type=0 rejected by i2pd** | MEDIUM | If i2pd rejects the destination during integration testing, revisit: change certificate to crypto_type=4, place X25519 pubkey in the 256-byte crypto field per i2pd `ECIES_X25519` key format. X25519 key is already derived. |
| **Tor header bytes wrong** | MEDIUM | Constants are pinned as byte literals in `src/tor.rs`. Golden test vector generated from a live Tor installation provides the definitive check. |
| **SHA3-256 vs SHA-256 for .onion checksum** | MEDIUM | `sha3` crate is a separate dependency from `sha2`. Lint: grep for any `Sha256` usage in `tor.rs` — must use `Sha3_256`. Golden test catches this. |
| **Daemon stdout not flushed** | MEDIUM | Explicit `io::stdout().flush()` after every `writeln!`. Code review gate: no `println!` in daemon.rs (println! does not guarantee flush in non-tty contexts). |
| **SIGTERM not handled — keys not zeroized** | MEDIUM | Add `ctrlc` or `signal-hook` crate; on signal, send `Command::Shutdown` via channel so graceful shutdown path runs. |
| **flake.nix cross-compilation broken** | MEDIUM | Phase 9 explicitly fixes `CARGO_BUILD_TARGET` and linker env var. Acceptance test: `file result/bin/hs-gen`. |
| **`recv_timeout` wakes slightly late** | LOW | After every `recv_timeout` timeout, recompute `unix_now() / validity` to get actual epoch — do not trust accumulated sleep. |
| **ed25519-dalek hazmat API removed** | LOW | The `hazmat` feature is stable in dalek 2.x. Pin exact version in Cargo.toml. |

---

## Verification Steps

| Criterion | Concrete Verification |
|-----------|-----------------------|
| Determinism | `cargo test` property test with 100+ quickcheck iterations |
| Tor format correctness | Golden test pinned from `tor --keygen` reference output |
| `.onion` address format | `echo <hostname> \| wc -c` = 63 (62 + newline); ends with `.onion`; verifies with Tor |
| I2P format correctness | Run i2pd with `--conf` pointing destination.dat; check i2pd log for acceptance |
| Output dir structure | Integration test inspects filesystem paths and permission bits |
| Atomic writes | Kill process mid-write in test; verify no partial files |
| Daemon rotation | Integration test: `--validity 2`, assert two `rotated` events within 5 seconds |
| `set_validity` boundary | Integration test: set during epoch, verify current epoch unaffected |
| Password zeroized | Code review: `Zeroizing<>` wrapper drops before `run()` call; no password in daemon state |
| aarch64-musl binary | `file result/bin/hs-gen` shows static ARM64 |
| Event line length | Unit test: construct maximum event (longest valid addresses), assert `json.len() < 4096` |
| stdout flushed | Integration test: read event within 100ms of epoch boundary |

---

## ADR

### Decision
Synchronous two-thread daemon (`std::thread` + `mpsc::recv_timeout`), flat module structure (`src/{kdf,tor,i2p,output,daemon}.rs`), `clap` derive for CLI, no application framework, no async runtime.

### Drivers
1. Two event sources only (stdin commands + epoch timer) — no scheduler overhead justified
2. Static musl binary — minimize C dependencies and linker complexity
3. Elixir Port integration — synchronous line protocol; no async framing needed

### Alternatives Considered
| Alternative | Reason for Rejection |
|-------------|---------------------|
| Tokio async | +2 MB binary, musl cross-link friction, `spawn_blocking` needed for Argon2id, overkill for two-source select |
| mio event loop (async-less) | Premature — same complexity as two-thread for two sources; migration target if third source ever added |
| Abscissa framework | No subcommands, no config file; adds boilerplate with zero benefit |
| Single-thread non-blocking stdin | Requires `fcntl O_NONBLOCK` + `poll`; more complex and error-prone than a reader thread |

### Why Chosen
Two threads mapping to two event sources is the minimal correct solution. `recv_timeout` provides the timer without an async executor. The binary is smaller, the build is simpler, and the concurrency model is easy to reason about and test with subprocess-based integration tests.

### Consequences
- Thread spawn overhead: negligible (one long-lived thread)
- Testability: timing requires subprocess integration tests; unit tests of pure logic remain fast
- Migration path: if a third event source appears, replace `recv_timeout` loop with `mio::Poll` — same thread structure, different selector

### Follow-ups
- After Phase 4: dedicated code review of I2P `.dat` byte layout against i2pd source before Phase 5
- After Phase 7: 24-hour soak test with `--validity 60` to verify no timer drift accumulation
- Consider `--dry-run` flag (future): derive and print addresses without writing files
- Consider whether flake.nix devShell can drop OpenBao/Dex (unused for this tool; template inheritance)

---

## Changelog (Improvements Applied)

| Source | Finding | Resolution Applied |
|--------|---------|-------------------|
| Architect | Tor header bytes unspecified | Added exact byte literal constants to Constants section and Phase 3 |
| Architect | I2P crypto_type likely wrong | Resolved: use crypto_type=0 with zeroed ElGamal field; note to revisit if i2pd rejects |
| Architect | Daemon password reading contradicts spec | Phase 6 now explicitly distinguishes: one-shot reads until EOF, daemon reads first line |
| Architect | `recv_timeout` recomputation | Phase 7 daemon pseudocode explicitly rechecks `unix_now()` after each timeout |
| Critic | flake.nix cross-compilation non-functional | Phase 9 now includes explicit `CARGO_BUILD_TARGET` and linker env var fix |
| Critic | Argon2id salt underspecified | Constants section pins exact 16-byte salt as byte literal |
| Critic | HKDF salt parameter unspecified | Constants section documents empty salt as intentional (per RFC 5869) |
| Critic | SIGTERM not handled | Phase 7 adds signal handling via `ctrlc` crate, graceful shutdown via channel |
| Critic | Stdout format for one-shot mode unspecified | Phase 5 defines exact stdout format with section headers |
| Critic | Daemon error recovery unspecified | Phase 7 documents: write failures emit `error` event, daemon continues |
