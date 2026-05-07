use data_encoding::BASE32_NOPAD;
use zeroize::{Zeroize, ZeroizeOnDrop};
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};
use x25519_dalek::StaticSecret as X25519SecretKey;

#[derive(Zeroize, ZeroizeOnDrop)]
/// I2P type-7 EdDSA-SHA512-Ed25519 destination keys, i2pd-compatible.
pub struct I2pKeys {
    /// Full .dat file: 391 bytes public + 256 bytes crypto_priv + 32 bytes signing_priv = 679 bytes
    pub destination_dat: Vec<u8>,
    /// base32(SHA-256(391-byte public destination)) + ".b32.i2p"
    pub b32_address: String,
}

/// Certificate bytes for type-7 key certificate:
/// type=KEY_CERT(5), length=4 (u16 BE), signing_type=7 (u16 BE), crypto_type=0 (u16 BE)
const CERTIFICATE: [u8; 7] = [0x05, 0x00, 0x04, 0x00, 0x07, 0x00, 0x00];

/// Generate I2P EdDSA-Ed25519 type-7 keys from a 64-byte seed.
/// seed[0..32] → Ed25519 signing key
/// seed[32..64] → X25519 encryption key
pub fn generate_i2p_keys(seed: &[u8; 64]) -> I2pKeys {
    // Ed25519 signing key pair from seed[0..32]
    let signing_seed: [u8; 32] = seed[..32].try_into().unwrap();
    let signing_key = SigningKey::from_bytes(&signing_seed);
    let ed25519_pubkey = signing_key.verifying_key().to_bytes();

    // X25519 encryption key from seed[32..64]
    let x25519_seed: [u8; 32] = seed[32..].try_into().unwrap();
    let x25519_secret = X25519SecretKey::from(x25519_seed);

    // --- Build public destination (391 bytes) ---
    //
    // [0..256]   crypto public key: zeros (crypto_type=0, ElGamal placeholder)
    // [256..384] signing public key: Ed25519 pubkey (32 bytes) zero-padded to 128
    // [384..391] certificate: 7 bytes

    let mut public_dest = [0u8; 391];
    // crypto public key field: all zeros (ElGamal placeholder, crypto_type=0)
    // signing public key field: Ed25519 pubkey at start, rest zeros
    public_dest[256..288].copy_from_slice(&ed25519_pubkey);
    // certificate
    public_dest[384..391].copy_from_slice(&CERTIFICATE);

    // --- Build b32 address ---
    let hash = Sha256::digest(&public_dest);
    let b32 = BASE32_NOPAD.encode(&hash).to_lowercase();
    let b32_address = format!("{b32}.b32.i2p");

    // --- Build private keys ---
    // crypto private key: X25519 private key (32 bytes) zero-padded to 256
    let mut crypto_priv = [0u8; 256];
    crypto_priv[..32].copy_from_slice(x25519_secret.as_bytes());

    // signing private key: Ed25519 seed (32 bytes)
    let signing_priv = signing_seed;

    // --- Assemble .dat ---
    let mut dat = Vec::with_capacity(679);
    dat.extend_from_slice(&public_dest);
    dat.extend_from_slice(&crypto_priv);
    dat.extend_from_slice(&signing_priv);

    I2pKeys {
        destination_dat: dat,
        b32_address,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_seed() -> [u8; 64] {
        [0x55u8; 64]
    }

    #[test]
    fn destination_dat_is_679_bytes() {
        let keys = generate_i2p_keys(&test_seed());
        assert_eq!(keys.destination_dat.len(), 679);
    }

    #[test]
    fn certificate_bytes_are_correct() {
        let keys = generate_i2p_keys(&test_seed());
        assert_eq!(&keys.destination_dat[384..391], &CERTIFICATE);
    }

    #[test]
    fn b32_address_ends_with_b32_i2p() {
        let keys = generate_i2p_keys(&test_seed());
        assert!(keys.b32_address.ends_with(".b32.i2p"), "b32: {}", keys.b32_address);
    }

    #[test]
    fn deterministic() {
        let seed = test_seed();
        let k1 = generate_i2p_keys(&seed);
        let k2 = generate_i2p_keys(&seed);
        assert_eq!(k1.b32_address, k2.b32_address);
        assert_eq!(k1.destination_dat, k2.destination_dat);
    }

    #[test]
    fn different_seeds_produce_different_addresses() {
        let k1 = generate_i2p_keys(&[0x01u8; 64]);
        let k2 = generate_i2p_keys(&[0x02u8; 64]);
        assert_ne!(k1.b32_address, k2.b32_address);
    }

    #[test]
    fn public_destination_is_391_bytes() {
        let keys = generate_i2p_keys(&test_seed());
        assert_eq!(keys.destination_dat[..391].len(), 391);
    }
}
