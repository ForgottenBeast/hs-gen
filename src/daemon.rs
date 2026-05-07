use std::io::{self, BufRead, Write};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::i2p::generate_i2p_keys;
use crate::kdf::{derive_epoch_seed, MasterKey, NetworkTag};
use crate::output::{write_i2p, write_tor, OutputTarget};
use crate::tor::generate_tor_keys;

#[derive(Debug, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
enum Command {
    SetValidity { seconds: u64 },
    Status,
    Shutdown,
    ForceRotate,
}

#[derive(Debug, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
enum Event {
    Started {
        epoch: u64,
        validity: u64,
    },
    Rotated {
        epoch: u64,
        validity: u64,
        tor_onion: Option<String>,
        i2p_b32: Option<String>,
        path: Option<String>,
    },
    ValidityChanged {
        new_validity: u64,
        effective_epoch: u64,
    },
    Status {
        epoch: u64,
        validity: u64,
        next_rotation_in: u64,
    },
    Error {
        msg: String,
    },
    Shutdown,
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before epoch")
        .as_secs()
}

fn emit(event: &Event) {
    let line = serde_json::to_string(event).expect("event serialization failed");
    let stdout = io::stdout();
    let mut out = stdout.lock();
    writeln!(out, "{line}").ok();
    out.flush().ok();
}

fn derive_and_write(
    master: &MasterKey,
    epoch: u64,
    gen_tor: bool,
    gen_i2p: bool,
    output_dir: &std::path::Path,
    overwrite: bool,
) -> (Option<String>, Option<String>) {
    let mut tor_onion: Option<String> = None;
    let mut i2p_b32: Option<String> = None;

    let target = OutputTarget::Directory {
        path: output_dir.to_path_buf(),
        overwrite,
    };

    if gen_tor {
        let seed = derive_epoch_seed(master, epoch, NetworkTag::Tor);
        let seed_arr: &[u8; 32] = seed
            .as_slice()
            .try_into()
            .expect("tor seed must be 32 bytes");
        let keys = generate_tor_keys(seed_arr);
        tor_onion = Some(keys.hostname.clone());
        if let Err(e) = write_tor(&keys, epoch, &target) {
            emit(&Event::Error {
                msg: format!("tor write failed: {e}"),
            });
        }
    }

    if gen_i2p {
        let seed = derive_epoch_seed(master, epoch, NetworkTag::I2p);
        let seed_arr: &[u8; 64] = seed
            .as_slice()
            .try_into()
            .expect("i2p seed must be 64 bytes");
        let keys = generate_i2p_keys(seed_arr);
        i2p_b32 = Some(keys.b32_address.clone());
        if let Err(e) = write_i2p(&keys, epoch, &target) {
            emit(&Event::Error {
                msg: format!("i2p write failed: {e}"),
            });
        }
    }

    (tor_onion, i2p_b32)
}

pub struct DaemonArgs {
    pub gen_tor: bool,
    pub gen_i2p: bool,
    pub validity: u64,
    pub output_dir: std::path::PathBuf,
    pub overwrite: bool,
}

pub fn run(master: MasterKey, args: DaemonArgs) -> io::Result<()> {
    let (tx, rx) = mpsc::channel::<Command>();

    // Stdin reader thread: parses JSON commands, sends them on the channel.
    // On EOF or parse-unrecoverable error, sends Shutdown explicitly so the
    // main loop exits even if the ctrlc handler is still holding a sender.
    let tx_stdin = tx.clone();
    thread::spawn(move || {
        let stdin = io::stdin();
        for line in stdin.lock().lines() {
            match line {
                Ok(l) if !l.is_empty() => match serde_json::from_str::<Command>(&l) {
                    Ok(cmd) => {
                        if tx_stdin.send(cmd).is_err() {
                            return;
                        }
                    }
                    Err(_) => emit(&Event::Error {
                        msg: format!("invalid command JSON: {l}"),
                    }),
                },
                _ => break,
            }
        }
        // EOF (or read error): drop tx_stdin and exit the thread.
        // The daemon keeps running; only SIGTERM/SIGINT shuts it down.
    });

    // SIGTERM / Ctrl-C handler
    let tx_signal = tx.clone();
    ctrlc::set_handler(move || {
        let _ = tx_signal.send(Command::Shutdown);
    })
    .ok();
    drop(tx);

    let mut validity = args.validity;
    let mut pending_validity: Option<u64> = None;

    // Initial rotation
    let mut current_epoch = unix_now() / validity;
    let (tor_onion, i2p_b32) = derive_and_write(
        &master,
        current_epoch,
        args.gen_tor,
        args.gen_i2p,
        &args.output_dir,
        args.overwrite,
    );

    let mut current_tor_onion = tor_onion;
    let mut current_i2p_b32 = i2p_b32;

    emit(&Event::Started {
        epoch: current_epoch,
        validity,
    });
    let path = epoch_path(&args.output_dir, current_epoch, args.overwrite);
    emit(&Event::Rotated {
        epoch: current_epoch,
        validity,
        tor_onion: current_tor_onion.clone(),
        i2p_b32: current_i2p_b32.clone(),
        path,
    });
    write_status_json(
        &args.output_dir,
        current_epoch,
        validity,
        unix_now(),
        current_tor_onion.as_deref(),
        current_i2p_b32.as_deref(),
    );

    loop {
        let now = unix_now();
        let next_epoch_start = (current_epoch + 1) * validity;
        let sleep_secs = next_epoch_start.saturating_sub(now);
        let sleep = Duration::from_secs(sleep_secs.max(1));

        match rx.recv_timeout(sleep) {
            Err(mpsc::RecvTimeoutError::Timeout) => {
                let now = unix_now();
                let new_epoch = now / validity;
                if new_epoch > current_epoch {
                    if let Some(pv) = pending_validity.take() {
                        validity = pv;
                    }
                    current_epoch = new_epoch;
                    let (tor_onion, i2p_b32) = derive_and_write(
                        &master,
                        current_epoch,
                        args.gen_tor,
                        args.gen_i2p,
                        &args.output_dir,
                        args.overwrite,
                    );
                    current_tor_onion = tor_onion;
                    current_i2p_b32 = i2p_b32;
                    let path = epoch_path(&args.output_dir, current_epoch, args.overwrite);
                    emit(&Event::Rotated {
                        epoch: current_epoch,
                        validity,
                        tor_onion: current_tor_onion.clone(),
                        i2p_b32: current_i2p_b32.clone(),
                        path,
                    });
                    write_status_json(
                        &args.output_dir,
                        current_epoch,
                        validity,
                        unix_now(),
                        current_tor_onion.as_deref(),
                        current_i2p_b32.as_deref(),
                    );
                }
            }
            Ok(Command::ForceRotate) => {
                let new_epoch = current_epoch + 1;
                let (tor_onion, i2p_b32) = derive_and_write(
                    &master,
                    new_epoch,
                    args.gen_tor,
                    args.gen_i2p,
                    &args.output_dir,
                    args.overwrite,
                );
                current_epoch = new_epoch;
                current_tor_onion = tor_onion;
                current_i2p_b32 = i2p_b32;
                let path = epoch_path(&args.output_dir, current_epoch, args.overwrite);
                emit(&Event::Rotated {
                    epoch: current_epoch,
                    validity,
                    tor_onion: current_tor_onion.clone(),
                    i2p_b32: current_i2p_b32.clone(),
                    path,
                });
                write_status_json(
                    &args.output_dir,
                    current_epoch,
                    validity,
                    unix_now(),
                    current_tor_onion.as_deref(),
                    current_i2p_b32.as_deref(),
                );
            }
            Ok(Command::SetValidity { seconds }) => {
                if seconds < 60 {
                    emit(&Event::Error {
                        msg: "validity must be >= 60 seconds".to_string(),
                    });
                    continue;
                }
                pending_validity = Some(seconds);
                emit(&Event::ValidityChanged {
                    new_validity: seconds,
                    effective_epoch: current_epoch + 1,
                });
            }
            Ok(Command::Status) => {
                let now = unix_now();
                let next_rotation_in = ((current_epoch + 1) * validity).saturating_sub(now);
                emit(&Event::Status {
                    epoch: current_epoch,
                    validity,
                    next_rotation_in,
                });
                write_status_json(
                    &args.output_dir,
                    current_epoch,
                    validity,
                    now,
                    current_tor_onion.as_deref(),
                    current_i2p_b32.as_deref(),
                );
            }
            Ok(Command::Shutdown) | Err(mpsc::RecvTimeoutError::Disconnected) => {
                emit(&Event::Shutdown);
                break;
            }
        }
    }

    Ok(())
}

fn epoch_path(base: &std::path::Path, epoch: u64, overwrite: bool) -> Option<String> {
    if overwrite {
        Some(base.display().to_string())
    } else {
        Some(base.join(epoch.to_string()).display().to_string())
    }
}

#[derive(Serialize)]
struct StatusJson<'a> {
    epoch: u64,
    validity: u64,
    next_rotation_in: u64,
    tor_onion: Option<&'a str>,
    i2p_b32: Option<&'a str>,
}

fn write_status_json(
    output_dir: &std::path::Path,
    epoch: u64,
    validity: u64,
    now: u64,
    tor_onion: Option<&str>,
    i2p_b32: Option<&str>,
) {
    let next_rotation_in = ((epoch + 1) * validity).saturating_sub(now);
    let s = StatusJson {
        epoch,
        validity,
        next_rotation_in,
        tor_onion,
        i2p_b32,
    };
    if let Ok(json) = serde_json::to_string(&s) {
        let path = output_dir.join("status.json");
        let tmp = path.with_extension("json.tmp");
        if std::fs::write(&tmp, json.as_bytes()).is_ok() {
            let _ = std::fs::rename(&tmp, &path);
        }
    }
}
