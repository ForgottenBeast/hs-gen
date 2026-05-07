use argon2::{Argon2, Params, Version};
use hkdf::Hkdf;
use sha2::Sha512;
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Salt for Argon2id password stretch — fixed 16-byte domain separator.
const ARGON2_SALT: &[u8; 16] = b"hs-gen-v1\x00\x00\x00\x00\x00\x00\x00";

/// Argon2id parameters: OWASP recommended minimums.
const ARGON2_M_COST: u32 = 19456; // 19 MiB
const ARGON2_T_COST: u32 = 2;
const ARGON2_P_COST: u32 = 1;

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MasterKey([u8; 32]);

impl MasterKey {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Clone, Copy)]
pub enum NetworkTag {
    Tor,
    I2p,
}

impl NetworkTag {
    fn tag_bytes(self) -> &'static [u8] {
        match self {
            NetworkTag::Tor => b"tor-v3",
            NetworkTag::I2p => b"i2p-ed25519",
        }
    }

    pub fn seed_len(self) -> usize {
        match self {
            NetworkTag::Tor => 32,
            NetworkTag::I2p => 64,
        }
    }
}

/// Derive master key from password using Argon2id.
/// The password bytes are consumed and zeroized by the caller after this returns.
pub fn derive_master_key(password: &[u8]) -> Result<MasterKey, argon2::Error> {
    let params = Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, Some(32))
        .map_err(|_| argon2::Error::AdTooLong)?;
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, Version::V0x13, params);

    let mut output = [0u8; 32];
    argon2
        .hash_password_into(password, ARGON2_SALT, &mut output)
        .map_err(|_| argon2::Error::AdTooLong)?;

    Ok(MasterKey(output))
}

/// Derive a per-epoch, per-network seed using HKDF-SHA512.
/// `epoch` is `unix_timestamp_secs / validity_secs`.
pub fn derive_epoch_seed(
    master: &MasterKey,
    epoch: u64,
    network: NetworkTag,
) -> Zeroizing<Vec<u8>> {
    let len = network.seed_len();
    let mut info = Vec::with_capacity(8 + network.tag_bytes().len());
    info.extend_from_slice(&epoch.to_le_bytes());
    info.extend_from_slice(network.tag_bytes());

    let hk = Hkdf::<Sha512>::new(None, master.as_bytes());
    let mut okm = Zeroizing::new(vec![0u8; len]);
    hk.expand(&info, &mut okm)
        .expect("HKDF expand failed: output too long");
    okm
}

/// Compute the current epoch for a given validity window.
pub fn current_epoch(validity_secs: u64) -> u64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before UNIX_EPOCH")
        .as_secs();
    now / validity_secs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn master_key_is_deterministic() {
        let k1 = derive_master_key(b"hunter2").unwrap();
        let k2 = derive_master_key(b"hunter2").unwrap();
        assert_eq!(k1.0, k2.0);
    }

    #[test]
    fn master_key_differs_by_password() {
        let k1 = derive_master_key(b"password1").unwrap();
        let k2 = derive_master_key(b"password2").unwrap();
        assert_ne!(k1.0, k2.0);
    }

    #[test]
    fn epoch_seeds_differ_by_epoch() {
        let master = derive_master_key(b"test").unwrap();
        let s1 = derive_epoch_seed(&master, 0, NetworkTag::Tor);
        let s2 = derive_epoch_seed(&master, 1, NetworkTag::Tor);
        assert_ne!(*s1, *s2);
    }

    #[test]
    fn epoch_seeds_differ_by_network() {
        let master = derive_master_key(b"test").unwrap();
        let tor = derive_epoch_seed(&master, 42, NetworkTag::Tor);
        let i2p = derive_epoch_seed(&master, 42, NetworkTag::I2p);
        assert_ne!(*tor, *i2p);
    }

    #[test]
    fn epoch_seed_is_deterministic() {
        let master = derive_master_key(b"test").unwrap();
        let s1 = derive_epoch_seed(&master, 99, NetworkTag::Tor);
        let s2 = derive_epoch_seed(&master, 99, NetworkTag::Tor);
        assert_eq!(*s1, *s2);
    }

    #[test]
    fn tor_seed_is_32_bytes() {
        let master = derive_master_key(b"test").unwrap();
        let seed = derive_epoch_seed(&master, 0, NetworkTag::Tor);
        assert_eq!(seed.len(), 32);
    }

    #[test]
    fn i2p_seed_is_64_bytes() {
        let master = derive_master_key(b"test").unwrap();
        let seed = derive_epoch_seed(&master, 0, NetworkTag::I2p);
        assert_eq!(seed.len(), 64);
    }
}

#[cfg(test)]
mod props {
    use super::*;
    use quickcheck_macros::quickcheck;

    #[quickcheck]
    fn kdf_is_deterministic(password: Vec<u8>, epoch: u64) -> bool {
        let Ok(master) = derive_master_key(&password) else {
            return true;
        };
        let s1 = derive_epoch_seed(&master, epoch, NetworkTag::Tor);
        let s2 = derive_epoch_seed(&master, epoch, NetworkTag::Tor);
        *s1 == *s2
    }
}
