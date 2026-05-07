use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use crate::i2p::I2pKeys;
use crate::tor::TorKeys;
use data_encoding::BASE64;

pub enum OutputTarget {
    Stdout,
    Directory { path: PathBuf, overwrite: bool },
}

/// Write Tor keys to the chosen target.
pub fn write_tor(keys: &TorKeys, epoch: u64, target: &OutputTarget) -> io::Result<()> {
    match target {
        OutputTarget::Stdout => {
            let stdout = io::stdout();
            let mut out = stdout.lock();
            writeln!(out, "=== TOR ===")?;
            writeln!(out, "onion: {}", keys.hostname)?;
            writeln!(
                out,
                "secret_key (base64): {}",
                BASE64.encode(&keys.secret_key_file[32..])
            )?;
            writeln!(
                out,
                "public_key (base64): {}",
                BASE64.encode(&keys.public_key_file[32..])
            )?;
            out.flush()
        }
        OutputTarget::Directory { path, overwrite } => {
            let tor_dir = service_dir(path, epoch, "tor", *overwrite);
            fs::create_dir_all(&tor_dir)?;
            atomic_write(&tor_dir.join("hs_ed25519_secret_key"), &keys.secret_key_file)?;
            atomic_write(&tor_dir.join("hs_ed25519_public_key"), &keys.public_key_file)?;
            atomic_write(
                &tor_dir.join("hostname"),
                keys.hostname.as_bytes(),
            )
        }
    }
}

/// Write I2P keys to the chosen target.
pub fn write_i2p(keys: &I2pKeys, epoch: u64, target: &OutputTarget) -> io::Result<()> {
    match target {
        OutputTarget::Stdout => {
            let stdout = io::stdout();
            let mut out = stdout.lock();
            writeln!(out, "=== I2P ===")?;
            writeln!(out, "b32: {}", keys.b32_address)?;
            writeln!(
                out,
                "destination (base64): {}",
                BASE64.encode(&keys.destination_dat[..391])
            )?;
            out.flush()
        }
        OutputTarget::Directory { path, overwrite } => {
            let i2p_dir = service_dir(path, epoch, "i2p", *overwrite);
            fs::create_dir_all(&i2p_dir)?;
            atomic_write(&i2p_dir.join("destination.dat"), &keys.destination_dat)?;
            atomic_write(
                &i2p_dir.join("destination.b32.i2p"),
                keys.b32_address.as_bytes(),
            )
        }
    }
}

fn service_dir(base: &Path, epoch: u64, network: &str, overwrite: bool) -> PathBuf {
    if overwrite {
        base.join(network)
    } else {
        base.join(epoch.to_string()).join(network)
    }
}

/// Write bytes to `path` atomically (write to .tmp then rename).
/// Sets file permissions to 0600 on Unix.
fn atomic_write(path: &Path, data: &[u8]) -> io::Result<()> {
    let tmp = path.with_extension("tmp");
    {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            f.set_permissions(fs::Permissions::from_mode(0o600))?;
        }

        f.write_all(data)?;
        f.flush()?;
    }
    fs::rename(&tmp, path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kdf::{derive_epoch_seed, derive_master_key, NetworkTag};
    use crate::tor::generate_tor_keys;
    use crate::i2p::generate_i2p_keys;
    use tempfile::TempDir;

    fn make_tor_keys() -> TorKeys {
        let master = derive_master_key(b"test").unwrap();
        let seed = derive_epoch_seed(&master, 0, NetworkTag::Tor);
        generate_tor_keys(seed.as_slice().try_into().unwrap())
    }

    fn make_i2p_keys() -> I2pKeys {
        let master = derive_master_key(b"test").unwrap();
        let seed = derive_epoch_seed(&master, 0, NetworkTag::I2p);
        generate_i2p_keys(seed.as_slice().try_into().unwrap())
    }

    #[test]
    fn tor_dir_no_overwrite_creates_epoch_subdir() {
        let dir = TempDir::new().unwrap();
        let target = OutputTarget::Directory {
            path: dir.path().to_path_buf(),
            overwrite: false,
        };
        write_tor(&make_tor_keys(), 42, &target).unwrap();
        assert!(dir.path().join("42/tor/hs_ed25519_secret_key").exists());
        assert!(dir.path().join("42/tor/hs_ed25519_public_key").exists());
        assert!(dir.path().join("42/tor/hostname").exists());
    }

    #[test]
    fn tor_dir_overwrite_writes_directly() {
        let dir = TempDir::new().unwrap();
        let target = OutputTarget::Directory {
            path: dir.path().to_path_buf(),
            overwrite: true,
        };
        write_tor(&make_tor_keys(), 99, &target).unwrap();
        assert!(dir.path().join("tor/hs_ed25519_secret_key").exists());
    }

    #[test]
    fn i2p_dir_no_overwrite_creates_epoch_subdir() {
        let dir = TempDir::new().unwrap();
        let target = OutputTarget::Directory {
            path: dir.path().to_path_buf(),
            overwrite: false,
        };
        write_i2p(&make_i2p_keys(), 7, &target).unwrap();
        assert!(dir.path().join("7/i2p/destination.dat").exists());
        assert!(dir.path().join("7/i2p/destination.b32.i2p").exists());
    }

    #[cfg(unix)]
    #[test]
    fn key_files_are_mode_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new().unwrap();
        let target = OutputTarget::Directory {
            path: dir.path().to_path_buf(),
            overwrite: false,
        };
        write_tor(&make_tor_keys(), 1, &target).unwrap();
        let meta = fs::metadata(dir.path().join("1/tor/hs_ed25519_secret_key")).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
    }
}
