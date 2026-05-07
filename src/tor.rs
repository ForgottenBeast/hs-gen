use data_encoding::BASE32_NOPAD;
use ed25519_dalek::hazmat::ExpandedSecretKey;
use sha2::Sha512;
use sha3::{Digest, Sha3_256};
use zeroize::{Zeroize, ZeroizeOnDrop};

const HEADER_SECRET: &[u8; 32] = b"== ed25519v1-secret: type0 ==\x00\x00\x00";
const HEADER_PUBLIC: &[u8; 32] = b"== ed25519v1-public: type0 ==\x00\x00\x00";
const ONION_CHECKSUM_PREFIX: &[u8] = b".onion checksum";
const ONION_VERSION: u8 = 0x03;

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct TorKeys {
    /// 96 bytes: HEADER_SECRET(32) + expanded_secret_key(64)
    pub secret_key_file: [u8; 96],
    /// 64 bytes: HEADER_PUBLIC(32) + ed25519_pubkey(32)
    pub public_key_file: [u8; 64],
    /// 62 chars: 56 base32 chars + ".onion"
    pub hostname: String,
}

/// Generate Tor v3 hidden service keys from a 32-byte seed.
pub fn generate_tor_keys(seed: &[u8; 32]) -> TorKeys {
    // Key-expand: SHA-512 of seed, then clamp
    let mut h: [u8; 64] = {
        use sha2::Digest;
        let mut hasher = Sha512::new();
        hasher.update(seed);
        hasher.finalize().into()
    };

    // Clamp the scalar (lower 32 bytes)
    h[0] &= 248;
    h[31] &= 63;
    h[31] |= 64;

    // Derive public key via ExpandedSecretKey
    let expanded = ExpandedSecretKey::from_bytes(&h);
    let pubkey = ed25519_dalek::VerifyingKey::from(&expanded);
    let pubkey_bytes = pubkey.to_bytes();

    // Build secret key file: header + clamped 64-byte expanded key
    let mut secret_key_file = [0u8; 96];
    secret_key_file[..32].copy_from_slice(HEADER_SECRET);
    secret_key_file[32..].copy_from_slice(&h);

    // Build public key file: header + 32-byte public key
    let mut public_key_file = [0u8; 64];
    public_key_file[..32].copy_from_slice(HEADER_PUBLIC);
    public_key_file[32..].copy_from_slice(&pubkey_bytes);

    // Build hostname: base32(pubkey || checksum[2] || version) + ".onion"
    // checksum = SHA3-256(".onion checksum" || pubkey || version)[0..2]
    let checksum = {
        let mut hasher = Sha3_256::new();
        hasher.update(ONION_CHECKSUM_PREFIX);
        hasher.update(pubkey_bytes);
        hasher.update([ONION_VERSION]);
        let result = hasher.finalize();
        [result[0], result[1]]
    };

    let mut addr_bytes = [0u8; 35]; // 32 + 2 + 1
    addr_bytes[..32].copy_from_slice(&pubkey_bytes);
    addr_bytes[32..34].copy_from_slice(&checksum);
    addr_bytes[34] = ONION_VERSION;

    let b32 = BASE32_NOPAD.encode(&addr_bytes).to_lowercase();
    let hostname = format!("{b32}.onion");

    TorKeys {
        secret_key_file,
        public_key_file,
        hostname,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_seed() -> [u8; 32] {
        [0x42u8; 32]
    }

    #[test]
    fn secret_key_file_is_96_bytes() {
        let keys = generate_tor_keys(&test_seed());
        assert_eq!(keys.secret_key_file.len(), 96);
    }

    #[test]
    fn secret_key_file_starts_with_header() {
        let keys = generate_tor_keys(&test_seed());
        assert_eq!(&keys.secret_key_file[..32], HEADER_SECRET);
    }

    #[test]
    fn public_key_file_is_64_bytes() {
        let keys = generate_tor_keys(&test_seed());
        assert_eq!(keys.public_key_file.len(), 64);
    }

    #[test]
    fn public_key_file_starts_with_header() {
        let keys = generate_tor_keys(&test_seed());
        assert_eq!(&keys.public_key_file[..32], HEADER_PUBLIC);
    }

    #[test]
    fn hostname_ends_with_onion() {
        let keys = generate_tor_keys(&test_seed());
        assert!(
            keys.hostname.ends_with(".onion"),
            "hostname: {}",
            keys.hostname
        );
    }

    #[test]
    fn hostname_is_62_chars() {
        let keys = generate_tor_keys(&test_seed());
        assert_eq!(
            keys.hostname.len(),
            62,
            "hostname len {}: {}",
            keys.hostname.len(),
            keys.hostname
        );
    }

    #[test]
    fn different_seeds_produce_different_hostnames() {
        let k1 = generate_tor_keys(&[0x01u8; 32]);
        let k2 = generate_tor_keys(&[0x02u8; 32]);
        assert_ne!(k1.hostname, k2.hostname);
    }

    #[test]
    fn generation_is_deterministic() {
        let seed = test_seed();
        let k1 = generate_tor_keys(&seed);
        let k2 = generate_tor_keys(&seed);
        assert_eq!(k1.hostname, k2.hostname);
        assert_eq!(k1.secret_key_file, k2.secret_key_file);
    }
}
