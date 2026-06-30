//! Pairing: SPAKE2 password-authenticated key agreement, augmented with a
//! per-session ephemeral X25519 exchange for **forward secrecy**, plus a
//! key-confirmation MAC step so each side proves it derived the same session
//! key (defeating an active MITM that completes both halves).
//!
//! # Wire format of a SPAKE2 message
//! `<spake2_group_element || 32-byte ephemeral X25519 public key>`. The
//! ephemeral public keys let both sides mix a fresh Diffie-Hellman shared
//! secret into the session key, so that even if the short 6-digit pairing
//! code is later brute-forced from a captured transcript, the ephemeral
//! private keys are gone and past recordings cannot be decrypted.
//!
//! # Flow
//!   A = start(A, code) -> (PairingA, msgA)   // msg = spake2_msg || eph_pub_A
//!   B = start(B, code) -> (PairingB, msgB)
//!   combinedA = A.finish(msgB)               combinedB = B.finish(msgA)   // equal iff same code
//!   keys      = SessionKeys::derive(combined)   // combined = spake2_secret || ecdh_secret
//!   A sends confirmation_token(keys, A) to B; B verifies
//!   B sends confirmation_token(keys, B) to A; A verifies
//!
//! # Security notes (C5)
//! - The 6-digit pairing code (~20 bits) resists **passive** eavesdropping
//!   but can be brute-forced offline from a captured handshake transcript.
//!   Forward secrecy (the ephemeral X25519) ensures such a later break does
//!   NOT decrypt previously recorded transfers.
//! - Key confirmation defeats an active MITM that terminates both halves.
//!   A terminating relay produces *different* session keys on each victim, so
//!   the rotating liveness code shown to the two humans will DIFFER — the
//!   liveness code is a human Short-Authentication-String (SAS) check; the
//!   backend does not auto-abort on mismatch, security depends on the humans
//!   comparing and aborting. See `liveness` module docs.

use anyhow::{anyhow, Result};
use rand::rngs::OsRng;
use spake2::{Ed25519Group, Identity, Password, Spake2};
use x25519_dalek::{EphemeralSecret, PublicKey};

use crate::crypto::{self, SessionKeys, MAC_LEN};

/// Length of the appended ephemeral X25519 public key on the wire.
const EPH_PUB_LEN: usize = 32;

/// The two sides of a pairing. Each role uses its own confirmation key
/// (confirm_a / confirm_b), which prevents reflection attacks.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Role {
    A,
    B,
}

/// In-progress SPAKE2 + ephemeral-X25519 handshake for one side.
pub struct Pairing {
    state: Spake2<Ed25519Group>,
    eph: EphemeralSecret,
}

impl Pairing {
    /// Begin a handshake as `role` using the human-typed pairing code.
    /// Returns the handshake state plus the message to send to the peer
    /// (`spake2_msg || 32-byte ephemeral public key`).
    pub fn start(role: Role, code: &str) -> (Pairing, Vec<u8>) {
        let password = Password::new(code.as_bytes());
        let id_a = Identity::new(b"frostwall/A");
        let id_b = Identity::new(b"frostwall/B");
        let (state, msg) = match role {
            Role::A => Spake2::<Ed25519Group>::start_a(&password, &id_a, &id_b),
            Role::B => Spake2::<Ed25519Group>::start_b(&password, &id_a, &id_b),
        };
        // Fresh per-session X25519 keypair for forward secrecy.
        let mut rng = OsRng;
        let eph = EphemeralSecret::random_from_rng(&mut rng);
        let eph_pub = PublicKey::from(&eph);

        let mut wire = msg;
        wire.extend_from_slice(eph_pub.as_bytes());
        (Pairing { state, eph }, wire)
    }

    /// Consume the peer's message (`spake2_msg || eph_pub`) and produce the
    /// combined shared secret = `spake2_secret || x25519_shared_secret`.
    /// Errors if the peer message is malformed or the X25519 public key is
    /// all-zero (the low-order point DH yields zero, which we reject).
    pub fn finish(self, peer_msg: &[u8]) -> Result<Vec<u8>> {
        if peer_msg.len() < EPH_PUB_LEN {
            return Err(anyhow!("peer handshake message too short"));
        }
        let split = peer_msg.len() - EPH_PUB_LEN;
        let (spake_msg, eph_pub_bytes) = peer_msg.split_at(split);

        let spake_secret = self
            .state
            .finish(spake_msg)
            .map_err(|_| anyhow!("SPAKE2 handshake failed (malformed peer message)"))?;

        let eph_pub_arr: [u8; EPH_PUB_LEN] = eph_pub_bytes
            .try_into()
            .map_err(|_| anyhow!("bad ephemeral public key length"))?;
        // Reject the all-zero key: its DH is the identity, offering no FS.
        if eph_pub_arr.iter().all(|&b| b == 0) {
            return Err(anyhow!("invalid ephemeral public key"));
        }
        let peer_pub = PublicKey::from(eph_pub_arr);
        let shared = self.eph.diffie_hellman(&peer_pub);
        if shared.was_contributory() == false {
            return Err(anyhow!("non-contributory ephemeral exchange"));
        }

        let mut combined = spake_secret;
        combined.extend_from_slice(shared.as_bytes());
        Ok(combined)
    }
}

/// Token `role` sends to prove it derived the session key.
pub fn confirmation_token(keys: &SessionKeys, role: Role) -> [u8; MAC_LEN] {
    let mac_key = match role {
        Role::A => &keys.confirm_a,
        Role::B => &keys.confirm_b,
    };
    crypto::confirmation_mac(mac_key, b"frostwall/v1/confirm")
}

/// Verify a peer's confirmation token in constant time.
pub fn verify_confirmation(keys: &SessionKeys, role: Role, token: &[u8]) -> bool {
    let expected = confirmation_token(keys, role);
    crypto::macs_equal(&expected, token)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn agree(code: &str) -> (SessionKeys, SessionKeys) {
        let (a, msg_a) = Pairing::start(Role::A, code);
        let (b, msg_b) = Pairing::start(Role::B, code);
        let sec_a = a.finish(&msg_b).unwrap();
        let sec_b = b.finish(&msg_a).unwrap();
        (SessionKeys::derive(&sec_a), SessionKeys::derive(&sec_b))
    }

    #[test]
    fn a_and_b_agree_on_secret() {
        let (a, msg_a) = Pairing::start(Role::A, "123456");
        let (b, msg_b) = Pairing::start(Role::B, "123456");
        let sec_a = a.finish(&msg_b).unwrap();
        let sec_b = b.finish(&msg_a).unwrap();
        assert_eq!(sec_a, sec_b);
        // combined secret is spake(32) || ecdh(32) = 64 bytes
        assert_eq!(sec_a.len(), 64);
    }

    #[test]
    fn mismatched_code_yields_different_secret() {
        let (a, msg_a) = Pairing::start(Role::A, "111111");
        let (b, msg_b) = Pairing::start(Role::B, "222222");
        let sec_a = a.finish(&msg_b).unwrap();
        let sec_b = b.finish(&msg_a).unwrap();
        assert_ne!(sec_a, sec_b);
    }

    #[test]
    fn honest_confirmation_round_trips() {
        let (keys_a, keys_b) = agree("654321");
        let token_a = confirmation_token(&keys_a, Role::A);
        assert!(verify_confirmation(&keys_b, Role::A, &token_a));
        let token_b = confirmation_token(&keys_b, Role::B);
        assert!(verify_confirmation(&keys_a, Role::B, &token_b));
    }

    #[test]
    fn confirmation_rejects_wrong_secret() {
        let (keys_good, _) = agree("good-code");
        let keys_bad = SessionKeys::derive(b"attacker-controlled-secret");
        let forged = confirmation_token(&keys_bad, Role::A);
        assert!(!verify_confirmation(&keys_good, Role::A, &forged));
    }

    #[test]
    fn finish_rejects_short_peer_message() {
        let (a, _msg_a) = Pairing::start(Role::A, "123456");
        // too short to contain an ephemeral public key
        assert!(a.finish(&[0u8; 10]).is_err());
    }

    #[test]
    fn finish_rejects_allzero_eph_pub() {
        let (a, msg_a) = Pairing::start(Role::A, "123456");
        // Replace the ephemeral tail with all-zero.
        let mut tampered = msg_a.clone();
        let len = tampered.len();
        tampered[len - EPH_PUB_LEN..].copy_from_slice(&[0u8; EPH_PUB_LEN]);
        // Build a B that will receive this tampered A message.
        let (b, _msg_b) = Pairing::start(Role::B, "123456");
        let _ = a;
        assert!(b.finish(&tampered).is_err());
    }

    #[test]
    fn tokens_differ_between_roles() {
        let (keys, _keys2) = agree("same-code");
        let a_tok = confirmation_token(&keys, Role::A);
        let b_tok = confirmation_token(&keys, Role::B);
        assert_ne!(a_tok, b_tok);
    }

    #[test]
    fn forward_secrecy_same_code_different_keys() {
        // Two independent pairings with the SAME code must derive DIFFERENT
        // session keys, because each uses fresh ephemerals. This is forward
        // secrecy: a code reused across sessions does not reuse keys.
        let (keys1_a, keys1_b) = agree("reused-code");
        assert_eq!(keys1_a.file_key, keys1_b.file_key); // within one session they match
        let (keys2_a, _) = agree("reused-code");
        assert_ne!(keys1_a.file_key, keys2_a.file_key); // across sessions they differ
    }
}
