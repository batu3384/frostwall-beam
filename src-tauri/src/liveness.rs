//! Liveness / identity code: a TOTP-style 6-digit code derived from the
//! session's `liveness_key` and the current time period. Both devices show
//! the same rotating code while connected; a mismatch reveals a MITM or a
//! dropped session. Refreshes every `STEP_SECS` seconds.
//!
//! # Security model (human SAS check)
//! This is a **human Short-Authentication-String (SAS) comparison**: the
//! backend computes and displays it, but does NOT auto-abort on mismatch.
//! Security depends on the humans comparing the two codes and aborting if
//! they differ. Because a terminating MITM relay runs two separate SPAKE2
//! exchanges, each victim derives a *different* session key, so their
//! liveness codes will differ and the humans can detect the relay.
//! A mismatch can also be caused by clock skew across a 30s boundary —
//! if the codes disagree only fleetingly at the rotation edge, wait a
//! moment and re-compare before aborting.

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::crypto::MAC_LEN;

/// Seconds each code is valid before rotating.
pub const STEP_SECS: u64 = 30;

/// Map a wall-clock second to its code period.
pub fn period_for(now_unix_secs: u64) -> u64 {
    now_unix_secs / STEP_SECS
}

/// Compute the 6-digit code for a specific period.
pub fn code_for_period(liveness_key: &[u8; MAC_LEN], period: u64) -> String {
    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(liveness_key).expect("HMAC accepts any key length");
    mac.update(&period.to_be_bytes());
    let bytes = mac.finalize().into_bytes();
    // HOTP-style dynamic truncation on the 32-byte HMAC-SHA256 output.
    let offset = (bytes[bytes.len() - 1] & 0x0f) as usize;
    let truncated =
        u32::from_be_bytes([bytes[offset], bytes[offset + 1], bytes[offset + 2], bytes[offset + 3]])
            & 0x7fff_ffff;
    format!("{:06}", (truncated as u64) % 1_000_000)
}

/// Compute the 6-digit code valid at `now_unix_secs`.
pub fn current_code(liveness_key: &[u8; MAC_LEN], now_unix_secs: u64) -> String {
    code_for_period(liveness_key, period_for(now_unix_secs))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(seed: u8) -> [u8; MAC_LEN] {
        [seed; MAC_LEN]
    }

    #[test]
    fn same_key_and_period_give_same_code() {
        let k = key(7);
        assert_eq!(code_for_period(&k, 1000), code_for_period(&k, 1000));
    }

    #[test]
    fn different_keys_give_different_codes() {
        let a = code_for_period(&key(1), 1000);
        let b = code_for_period(&key(2), 1000);
        assert_ne!(a, b);
    }

    #[test]
    fn code_rotates_between_periods() {
        let k = key(3);
        // try several periods; at least one must differ from period 0
        let c0 = code_for_period(&k, 0);
        let mut changed = false;
        for p in 1..6 {
            if code_for_period(&k, p) != c0 {
                changed = true;
                break;
            }
        }
        assert!(changed, "code should change across periods");
    }

    #[test]
    fn code_is_six_digits() {
        let c = code_for_period(&key(9), 42);
        assert_eq!(c.len(), 6);
        assert!(c.chars().all(|ch| ch.is_ascii_digit()));
    }

    #[test]
    fn period_for_divides_by_step() {
        assert_eq!(period_for(0), 0);
        assert_eq!(period_for(29), 0);
        assert_eq!(period_for(30), 1);
        assert_eq!(period_for(89), 2);
    }

    #[test]
    fn current_code_matches_code_for_period() {
        let k = key(5);
        let now = 123_456;
        assert_eq!(current_code(&k, now), code_for_period(&k, period_for(now)));
    }
}
