use std::io::{self, Read};
use std::path::PathBuf;

use clap::Parser;
use zeroize::Zeroizing;

use hs_gen::daemon::{run as daemon_run, DaemonArgs};
use hs_gen::i2p::generate_i2p_keys;
use hs_gen::kdf::{current_epoch, derive_epoch_seed, derive_master_key, NetworkTag};
use hs_gen::output::{write_i2p, write_tor, OutputTarget};
use hs_gen::tor::generate_tor_keys;

#[derive(Parser, Debug)]
#[command(name = "hs-gen", about = "Deterministic hidden service key generator")]
struct Args {
    /// Generate Tor v3 hidden service keys
    #[arg(long)]
    tor: bool,

    /// Generate I2P EdDSA-Ed25519 destination keys
    #[arg(long)]
    i2p: bool,

    /// Epoch length in seconds (minimum 60, default 3600)
    #[arg(long, default_value = "3600")]
    validity: u64,

    /// Write service directory files here (required for --daemon)
    #[arg(long)]
    output_dir: Option<PathBuf>,

    /// Overwrite existing files in output-dir (default: create per-epoch subdirectory)
    #[arg(long)]
    overwrite: bool,

    /// Run as daemon: auto-rotate at epoch boundaries, accept JSON commands on stdin
    #[arg(long)]
    daemon: bool,
}

fn main() {
    let mut args = Args::parse();

    // Default: generate both networks when neither flag is specified
    if !args.tor && !args.i2p {
        args.tor = true;
        args.i2p = true;
    }

    // Validation
    if args.validity < 60 {
        eprintln!("error: --validity must be >= 60 seconds");
        std::process::exit(1);
    }
    if args.daemon && args.output_dir.is_none() {
        eprintln!("error: --daemon requires --output-dir");
        std::process::exit(1);
    }

    if args.daemon {
        run_daemon(args);
    } else {
        run_oneshot(args);
    }
}

fn run_oneshot(args: Args) {
    // Read password until EOF
    let mut password_buf = Zeroizing::new(Vec::new());
    if let Err(e) = io::stdin().read_to_end(&mut password_buf) {
        eprintln!("error reading password: {e}");
        std::process::exit(1);
    }
    // Trim trailing newline
    if password_buf.last() == Some(&b'\n') {
        password_buf.pop();
    }
    if password_buf.last() == Some(&b'\r') {
        password_buf.pop();
    }

    let master = match derive_master_key(&password_buf) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("error: KDF failed: {e}");
            std::process::exit(1);
        }
    };

    let epoch = current_epoch(args.validity);
    let target = match &args.output_dir {
        Some(path) => OutputTarget::Directory {
            path: path.clone(),
            overwrite: args.overwrite,
        },
        None => OutputTarget::Stdout,
    };

    if args.tor {
        let seed = derive_epoch_seed(&master, epoch, NetworkTag::Tor);
        let seed_arr: &[u8; 32] = seed.as_slice().try_into().unwrap();
        let keys = generate_tor_keys(seed_arr);
        if let Err(e) = write_tor(&keys, epoch, &target) {
            eprintln!("error writing tor keys: {e}");
            std::process::exit(1);
        }
    }

    if args.i2p {
        let seed = derive_epoch_seed(&master, epoch, NetworkTag::I2p);
        let seed_arr: &[u8; 64] = seed.as_slice().try_into().unwrap();
        let keys = generate_i2p_keys(seed_arr);
        if let Err(e) = write_i2p(&keys, epoch, &target) {
            eprintln!("error writing i2p keys: {e}");
            std::process::exit(1);
        }
    }
}

fn run_daemon(args: Args) {
    // Daemon mode: read password as first line only
    let mut password_line = String::new();
    if let Err(e) = io::stdin().read_line(&mut password_line) {
        eprintln!("error reading password: {e}");
        std::process::exit(1);
    }
    // Trim trailing newline
    let password_trimmed = password_line.trim_end_matches(['\n', '\r']);
    let password_bytes = Zeroizing::new(password_trimmed.as_bytes().to_vec());

    let master = match derive_master_key(&password_bytes) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("error: KDF failed: {e}");
            std::process::exit(1);
        }
    };
    drop(password_bytes);
    drop(password_line);

    let output_dir = args.output_dir.unwrap(); // validated above
    let daemon_args = DaemonArgs {
        gen_tor: args.tor,
        gen_i2p: args.i2p,
        validity: args.validity,
        output_dir,
        overwrite: args.overwrite,
    };

    if let Err(e) = daemon_run(master, daemon_args) {
        eprintln!("daemon error: {e}");
        std::process::exit(1);
    }
}
