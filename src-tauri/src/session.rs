//! Session orchestration: turns a freshly-opened framed connection into a
//! paired, encrypted session via SPAKE2 + key confirmation, and exposes the
//! live connection + derived keys + rotating liveness code to the rest of the
//! app.
//!
//! # Handshake wire sequence (authoritative)
//!
//! Each handshake message is a single length-delimited frame (see `transport`)
//! whose payload is `<version byte> || bincode(Message)` only for the transfer
//! layer. During pairing the frames carry **raw bytes**, not `Message`s:
//!
//! ```text
//! Host (Role A)                Joiner (Role B)
//!   msgA = spake2_A || eph_pubA  ──(1)──▶
//!                               ◀──(2)──  msgB = spake2_B || eph_pubB
//!   tokA = MAC(confirm_a)        ──(3)──▶
//!                               ◀──(4)──  tokB = MAC(confirm_b)
//! ```
//!
//! - Host is **always Role A**, joiner is **always Role B**.
//! - `combined = spake2_secret || x25519(eph_priv, peer_eph_pub)`; the session
//!   keys are `SessionKeys::derive(combined)`.
//! - `tokA`/`tokB` are key-confirmation MACs; each side verifies the peer's
//!   token before the session is established. A wrong code or a terminating
//!   MITM fails here.
//! - Each recv() is bounded by `HANDSHAKE_TIMEOUT` (slowloris defense).
//!   Reordering any step deadlocks the handshake with no further error.

use std::time::Duration;

use anyhow::{anyhow, Result};
use rand::Rng;

use crate::crypto::SessionKeys;
use crate::liveness;
use crate::pairing::{self, Role};
use crate::transport::Connection;

/// Per-message timeout during the SPAKE2 handshake. A peer that opens the TCP
/// connection then stalls (slowloris) is dropped instead of wedging the
/// single accept slot indefinitely.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// A random 6-digit pairing code for the host to display.
pub fn generate_pairing_code() -> String {
    let n: u32 = rand::thread_rng().gen_range(0..1_000_000);
    format!("{:06}", n)
}

/// Receive one frame, but abort if the peer stalls past `HANDSHAKE_TIMEOUT`.
async fn recv_or_timeout(conn: &mut Connection) -> Result<Vec<u8>> {
    match tokio::time::timeout(HANDSHAKE_TIMEOUT, conn.recv()).await {
        Ok(r) => r,
        Err(_) => Err(anyhow!("handshake timed out (peer stalled)")),
    }
}

/// An established, paired, encrypted session.
pub struct Session {
    conn: Connection,
    keys: SessionKeys,
}

impl Session {
    pub fn new(conn: Connection, keys: SessionKeys) -> Self {
        Session { conn, keys }
    }

    pub fn keys(&self) -> &SessionKeys {
        &self.keys
    }

    pub fn conn_mut(&mut self) -> &mut Connection {
        &mut self.conn
    }

    /// The rotating 6-digit liveness code valid at `now_unix` seconds.
    pub fn liveness_code(&self, now_unix: u64) -> String {
        liveness::current_code(&self.keys.liveness_key, now_unix)
    }

    /// Destructure into the owned connection + keys.
    pub fn into_parts(self) -> (Connection, SessionKeys) {
        (self.conn, self.keys)
    }
}

/// Host side of the pairing handshake. Consumes the accepted connection and
/// returns a session on success.
pub async fn host_handshake(mut conn: Connection, code: &str) -> Result<Session> {
    let (pairing_state, msg_a) = pairing::Pairing::start(Role::A, code);
    conn.send(&msg_a).await?;
    let msg_b = recv_or_timeout(&mut conn).await?;
    let secret = pairing_state.finish(&msg_b)?;
    let keys = SessionKeys::derive(&secret);

    // Prove we derived the key, and require the peer to prove the same.
    let our_tok = pairing::confirmation_token(&keys, Role::A);
    conn.send(&our_tok).await?;
    let their_tok = recv_or_timeout(&mut conn).await?;
    if !pairing::verify_confirmation(&keys, Role::B, &their_tok) {
        return Err(anyhow!("key confirmation failed (wrong code or MITM)"));
    }
    Ok(Session::new(conn, keys))
}

/// Joiner side of the pairing handshake. Consumes a connection to the host.
pub async fn joiner_handshake(mut conn: Connection, code: &str) -> Result<Session> {
    let (pairing_state, msg_b) = pairing::Pairing::start(Role::B, code);
    let msg_a = recv_or_timeout(&mut conn).await?;
    conn.send(&msg_b).await?;
    let secret = pairing_state.finish(&msg_a)?;
    let keys = SessionKeys::derive(&secret);

    let their_tok = recv_or_timeout(&mut conn).await?;
    if !pairing::verify_confirmation(&keys, Role::A, &their_tok) {
        return Err(anyhow!("key confirmation failed (wrong code or MITM)"));
    }
    let our_tok = pairing::confirmation_token(&keys, Role::B);
    conn.send(&our_tok).await?;
    Ok(Session::new(conn, keys))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport;

    async fn loopback_pair() -> (Connection, Connection) {
        let listener = transport::bind(0).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { transport::accept(&listener).await.unwrap() });
        let client = transport::connect(addr).await.unwrap();
        (client, server.await.unwrap())
    }

    #[test]
    fn pairing_code_is_six_digits() {
        for _ in 0..100 {
            let c = generate_pairing_code();
            assert_eq!(c.len(), 6);
            assert!(c.chars().all(|ch| ch.is_ascii_digit()));
        }
    }

    #[tokio::test]
    async fn handshake_agrees_and_liveness_matches() {
        let (a, b) = loopback_pair().await;
        let code = "246813";
        let host_task = tokio::spawn(async move { host_handshake(a, code).await });

        let joiner = joiner_handshake(b, code).await.unwrap();
        let host = host_task.await.unwrap().unwrap();

        let now = 1_700_000_000u64;
        assert_eq!(host.liveness_code(now), joiner.liveness_code(now));
        // and the shared file key must match
        assert_eq!(host.keys().file_key, joiner.keys().file_key);
    }

    #[tokio::test]
    async fn handshake_rejects_mismatched_code() {
        let (a, b) = loopback_pair().await;
        let host_task = tokio::spawn(async move { host_handshake(a, "111111").await });

        let joiner = joiner_handshake(b, "222222").await;
        let host = host_task.await;

        assert!(joiner.is_err(), "joiner must reject mismatched code");
        assert!(host.unwrap().is_err(), "host must reject mismatched code");
    }
}
