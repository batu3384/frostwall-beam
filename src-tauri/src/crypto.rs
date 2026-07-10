//! Crypto primitives: HKDF-SHA256 key schedule, XChaCha20-Poly1305 AEAD,
//! and HMAC-SHA256 key-confirmation MACs.
//!
//! Everything here is pure and synchronous so it is trivial to unit-test.

use anyhow::{anyhow, Result};
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    XChaCha20Poly1305, XNonce,
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

/// Length of the SPAKE2 session secret we derive everything from.
pub const SESSION_KEY_LEN: usize = 32;
/// XChaCha20-Poly1305 key length.
pub const AEAD_KEY_LEN: usize = 32;
/// XChaCha20 nonce length (24 bytes).
pub const NONCE_LEN: usize = 24;
/// HMAC-SHA256 output length.
pub const MAC_LEN: usize = 32;

/// Sub-keys derived from the SPAKE2 session secret via HKDF-SHA256.
///
/// Each purpose gets its own independent key, so a weakness in one channel
/// (e.g. the liveness code leaking) cannot compromise file encryption.
#[derive(Clone)]
pub struct SessionKeys {
    /// Encrypts/decrypts every transferred file chunk.
    pub file_key: [u8; AEAD_KEY_LEN],
    /// MAC key the initiator (A) uses to prove it derived the session key.
    pub confirm_a: [u8; MAC_LEN],
    /// MAC key the responder (B) uses to prove it derived the session key.
    pub confirm_b: [u8; MAC_LEN],
    /// Encrypts/decrypts control-plane messages (manifest, accept, done, …).
    pub control_key: [u8; AEAD_KEY_LEN],
    /// Seed for the rotating 6-digit liveness code.
    pub liveness_key: [u8; MAC_LEN],
}

impl SessionKeys {
    /// Derive all sub-keys from the SPAKE2 shared secret.
    pub fn derive(session_secret: &[u8]) -> SessionKeys {
        let hk = Hkdf::<Sha256>::new(None, session_secret);
        let expand = |info: &'static [u8], buf: &mut [u8]| {
            hk.expand(info, buf)
                .expect("HKDF-SHA256 expand fits within 255*HashLen");
        };
        let mut file_key = [0u8; AEAD_KEY_LEN];
        let mut confirm_a = [0u8; MAC_LEN];
        let mut confirm_b = [0u8; MAC_LEN];
        let mut control_key = [0u8; AEAD_KEY_LEN];
        let mut liveness_key = [0u8; MAC_LEN];
        expand(b"frostwall/v1/file-key", &mut file_key);
        expand(b"frostwall/v1/confirm-a", &mut confirm_a);
        expand(b"frostwall/v1/confirm-b", &mut confirm_b);
        expand(b"frostwall/v1/control-key", &mut control_key);
        expand(b"frostwall/v1/liveness", &mut liveness_key);
        SessionKeys {
            file_key,
            confirm_a,
            confirm_b,
            control_key,
            liveness_key,
        }
    }
}

/// Encrypt a plaintext chunk. Returns `nonce || ciphertext+tag`.
pub fn encrypt_chunk(key: &[u8; AEAD_KEY_LEN], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng); // 24 random bytes
    let ct = cipher
        .encrypt(XNonce::from_slice(&nonce), plaintext)
        .map_err(|_| anyhow!("AEAD encryption failed"))?;
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Decrypt a packed chunk (`nonce || ciphertext+tag`).
pub fn decrypt_chunk(key: &[u8; AEAD_KEY_LEN], packed: &[u8]) -> Result<Vec<u8>> {
    if packed.len() < NONCE_LEN {
        return Err(anyhow!("ciphertext shorter than nonce"));
    }
    let (nonce_bytes, ct) = packed.split_at(NONCE_LEN);
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(XNonce::from_slice(nonce_bytes), ct)
        .map_err(|_| anyhow!("AEAD decryption failed (wrong key or tampered)"))
}

/// HMAC-SHA256 confirmation token proving possession of a session sub-key.
pub fn confirmation_mac(mac_key: &[u8; MAC_LEN], label: &[u8]) -> [u8; MAC_LEN] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(mac_key).expect("HMAC accepts any key length");
    mac.update(label);
    let mut out = [0u8; MAC_LEN];
    out.copy_from_slice(&mac.finalize().into_bytes());
    out
}

/// Constant-time comparison of two MACs / tags.
pub fn macs_equal(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_is_deterministic_for_same_secret() {
        let a = SessionKeys::derive(b"secret-1");
        let b = SessionKeys::derive(b"secret-1");
        assert_eq!(a.file_key, b.file_key);
        assert_eq!(a.confirm_a, b.confirm_a);
        assert_eq!(a.confirm_b, b.confirm_b);
        assert_eq!(a.liveness_key, b.liveness_key);
    }

    #[test]
    fn derive_differs_for_different_secrets() {
        let a = SessionKeys::derive(b"secret-1");
        let b = SessionKeys::derive(b"secret-2");
        assert_ne!(a.file_key, b.file_key);
        assert_ne!(a.liveness_key, b.liveness_key);
    }

    #[test]
    fn chunk_round_trips() {
        let key = SessionKeys::derive(b"k").file_key;
        let msg = b"hello world payload";
        let ct = encrypt_chunk(&key, msg).unwrap();
        assert_ne!(&ct[..], &msg[..]);
        let pt = decrypt_chunk(&key, &ct).unwrap();
        assert_eq!(pt, msg);
    }

    #[test]
    fn chunk_round_trips_large() {
        let key = SessionKeys::derive(b"k").file_key;
        let msg = vec![0xABu8; 1_000_000];
        let ct = encrypt_chunk(&key, &msg).unwrap();
        let pt = decrypt_chunk(&key, &ct).unwrap();
        assert_eq!(pt, msg);
    }

    #[test]
    fn chunk_two_encryptions_differ_for_same_plaintext() {
        // random nonce => ciphertexts differ
        let key = SessionKeys::derive(b"k").file_key;
        let a = encrypt_chunk(&key, b"same").unwrap();
        let b = encrypt_chunk(&key, b"same").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn decrypt_with_wrong_key_fails() {
        let k1 = SessionKeys::derive(b"a").file_key;
        let k2 = SessionKeys::derive(b"b").file_key;
        let ct = encrypt_chunk(&k1, b"secret").unwrap();
        assert!(decrypt_chunk(&k2, &ct).is_err());
    }

    #[test]
    fn decrypt_tampered_fails() {
        let key = SessionKeys::derive(b"k").file_key;
        let mut ct = encrypt_chunk(&key, b"secret").unwrap();
        let last = ct.len() - 1;
        ct[last] ^= 0xFF;
        assert!(decrypt_chunk(&key, &ct).is_err());
    }

    #[test]
    fn confirmation_mac_is_deterministic() {
        let keys = SessionKeys::derive(b"secret");
        let m1 = confirmation_mac(&keys.confirm_a, b"A->B");
        let m2 = confirmation_mac(&keys.confirm_a, b"A->B");
        assert_eq!(m1, m2);
    }

    #[test]
    fn confirmation_mac_differs_by_key() {
        let keys = SessionKeys::derive(b"secret");
        let from_a = confirmation_mac(&keys.confirm_a, b"confirm");
        let from_b = confirmation_mac(&keys.confirm_b, b"confirm");
        assert_ne!(from_a, from_b);
    }
}
