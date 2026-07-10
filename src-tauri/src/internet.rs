//! Internet transport: NAT-traversing P2P connections via `iroh` (QUIC,
//! hole-punching, relay fallback), paired with a tiny mailbox rendezvous
//! service so the existing 6-digit pairing code can also resolve a peer
//! that's on a *different* network entirely — not just the LAN.
//!
//! # Wire model
//!
//! Each side opens one outbound iroh uni-directional stream and accepts one
//! inbound uni-directional stream; joined together (`tokio::io::join`) they
//! form the same duplex byte pipe [`transport::Connection`] expects. This
//! deliberately avoids a single bi-directional stream: iroh only makes the
//! *receiver* aware of a stream once the sender writes to it, and our
//! handshake (`session::host_handshake`/`joiner_handshake`) has the host
//! speak first while the joiner reads first — two independent uni streams
//! let each direction proceed without waiting on the other.
//!
//! Everything above this layer (SPAKE2 pairing, AEAD encryption, Blake3
//! integrity, manifest validation) is unchanged: `session.rs`/`transfer.rs`
//! only ever call `Connection::send`/`recv` and have no idea whether the
//! bytes travelled over LAN TCP or an iroh relay.
//!
//! # Mailbox
//!
//! The mailbox (see the sibling `mailbox` crate) only ever stores
//! `code -> EndpointId` for a few minutes. It never sees file contents,
//! encryption keys, or the SPAKE2 handshake itself — those still flow
//! end-to-end between the two iroh endpoints.

use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use anyhow::{anyhow, Result};
use iroh::endpoint::presets;
use iroh::endpoint::{RecvStream, SendStream};
use iroh::{Endpoint, EndpointAddr, PublicKey};
use serde::{Deserialize, Serialize};
use tokio::io::{self, AsyncRead, AsyncWrite, ReadBuf};

use crate::transport::Connection;

/// QUIC ALPN identifying the Frostwall Beam wire protocol.
pub const ALPN: &[u8] = b"frostwall-beam/1";
/// How long to wait for the local iroh endpoint to come up (reach a home
/// relay) before giving up. On a network that blocks outbound UDP/QUIC this
/// would otherwise hang indefinitely instead of failing with a clear error.
const BIND_TIMEOUT: Duration = Duration::from_secs(20);
/// How long the host waits for a joiner to dial in before giving up.
const ACCEPT_TIMEOUT: Duration = Duration::from_secs(5 * 60);
/// How long the joiner waits for the peer connection itself to establish
/// (direct or relayed) before giving up.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
/// How long the joiner polls the mailbox for the host's address before
/// giving up (covers the host/joiner registering in either order).
const LOOKUP_TIMEOUT: Duration = Duration::from_secs(20);
/// Delay between mailbox lookup polls.
const LOOKUP_POLL_INTERVAL: Duration = Duration::from_millis(700);
/// How long to wait for both uni-directional streams to pair up after the
/// QUIC connection itself is established. A connection can succeed (handshake
/// complete) while the path is too lossy/asymmetric for streams to actually
/// open — without this, `open_uni`/`accept_uni` could hang forever instead of
/// surfacing a clear error.
const STREAM_PAIR_TIMEOUT: Duration = Duration::from_secs(30);

/// Start an iroh endpoint that can accept inbound Frostwall connections
/// (host side).
pub async fn host_endpoint() -> Result<Endpoint> {
    let bind = Endpoint::builder(presets::N0)
        .alpns(vec![ALPN.to_vec()])
        .bind();
    tokio::time::timeout(BIND_TIMEOUT, bind)
        .await
        .map_err(|_| anyhow!("timed out starting the internet endpoint (check your network/firewall)"))?
        .map_err(|e| anyhow!("failed to start internet endpoint: {e}"))
}

/// Start an iroh endpoint for outbound-only use (joiner side).
pub async fn join_endpoint() -> Result<Endpoint> {
    tokio::time::timeout(BIND_TIMEOUT, Endpoint::bind(presets::N0))
        .await
        .map_err(|_| anyhow!("timed out starting the internet endpoint (check your network/firewall)"))?
        .map_err(|e| anyhow!("failed to start internet endpoint: {e}"))
}

/// This endpoint's dialable identifier, to publish via the mailbox.
pub fn endpoint_id_string(ep: &Endpoint) -> String {
    ep.id().to_string()
}

/// Accept exactly one inbound connection and wrap it as a [`Connection`].
pub async fn accept_one(ep: &Endpoint) -> Result<Connection> {
    let incoming = tokio::time::timeout(ACCEPT_TIMEOUT, ep.accept())
        .await
        .map_err(|_| anyhow!("timed out waiting for an internet connection"))?
        .ok_or_else(|| anyhow!("internet endpoint closed before a peer connected"))?;
    let conn = incoming
        .await
        .map_err(|e| anyhow!("incoming connection failed: {e}"))?;
    pair_streams(ep, conn).await
}

/// Dial a peer by its published `EndpointId` string and wrap as a [`Connection`].
pub async fn connect_to(ep: &Endpoint, endpoint_id: &str) -> Result<Connection> {
    let id: PublicKey = endpoint_id
        .trim()
        .parse()
        .map_err(|_| anyhow!("invalid peer address"))?;
    let addr = EndpointAddr::new(id);
    let conn = tokio::time::timeout(CONNECT_TIMEOUT, ep.connect(addr, ALPN))
        .await
        .map_err(|_| anyhow!("timed out connecting to the peer"))?
        .map_err(|e| anyhow!("could not reach peer: {e}"))?;
    pair_streams(ep, conn).await
}

/// Open our outbound stream and accept the peer's, joining them into one
/// duplex pipe. Order matters only in that `open_uni` is a purely local,
/// non-blocking allocation — it never waits on the peer — so it's safe to
/// always open before accepting on both sides.
///
/// Wrapped in an overall timeout: the QUIC handshake can succeed while the
/// path is too asymmetric/lossy for streams to actually open (seen in
/// practice — a "connected" peer that never finishes pairing), which would
/// otherwise hang this call forever with no way for the caller to recover.
async fn pair_streams(ep: &Endpoint, conn: iroh::endpoint::Connection) -> Result<Connection> {
    tokio::time::timeout(STREAM_PAIR_TIMEOUT, async {
        let send = conn
            .open_uni()
            .await
            .map_err(|e| anyhow!("open outgoing stream: {e}"))?;
        let recv = conn
            .accept_uni()
            .await
            .map_err(|e| anyhow!("accept incoming stream: {e}"))?;
        Ok(Connection::from_io(EndpointBoundIo {
            io: io::join(recv, send),
            _endpoint: ep.clone(),
        }))
    })
    .await
    .map_err(|_| anyhow!("timed out establishing the data channel with the peer"))?
}

/// Wraps the joined stream pair together with a clone of the owning
/// [`Endpoint`]. The endpoint drives background tasks (hole-punching, relay
/// upkeep) that the connection depends on — dropping it early would be a
/// silent, hard-to-diagnose way to kill an otherwise-healthy session, so we
/// keep it alive for exactly as long as the byte pipe built on top of it is.
struct EndpointBoundIo {
    io: io::Join<RecvStream, SendStream>,
    _endpoint: Endpoint,
}

impl AsyncRead for EndpointBoundIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_read(cx, buf)
    }
}

impl AsyncWrite for EndpointBoundIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.io).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}

/// HTTP client for the mailbox rendezvous service: maps a pairing code to
/// the host's `EndpointId` so a joiner on a different network can dial it.
#[derive(Clone)]
pub struct Mailbox {
    base_url: String,
    http: reqwest::Client,
}

#[derive(Serialize)]
struct RegisterRequest<'a> {
    code: &'a str,
    endpoint_id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    device_name: Option<&'a str>,
}

#[derive(Deserialize)]
struct RegisterResponse {
    token: String,
}

#[derive(Deserialize)]
struct LookupResponse {
    endpoint_id: String,
    device_name: Option<String>,
}

impl Mailbox {
    pub fn new(base_url: impl Into<String>) -> Self {
        Mailbox {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            http: reqwest::Client::new(),
        }
    }

    /// Publish `code -> endpoint_id`. Returns a registration token required to
    /// unregister. The mailbox forgets this after a short TTL.
    pub async fn register(
        &self,
        code: &str,
        endpoint_id: &str,
        device_name: Option<&str>,
    ) -> Result<String> {
        let res = self
            .http
            .post(format!("{}/register", self.base_url))
            .json(&RegisterRequest {
                code,
                endpoint_id,
                device_name,
            })
            .send()
            .await
            .map_err(|e| anyhow!("mailbox unreachable: {e}"))?;
        if res.status().is_success() {
            let body: RegisterResponse = res
                .json()
                .await
                .map_err(|e| anyhow!("mailbox returned a malformed response: {e}"))?;
            Ok(body.token)
        } else if res.status() == reqwest::StatusCode::CONFLICT {
            Err(anyhow!("this pairing code is already registered"))
        } else {
            Err(anyhow!("mailbox rejected registration ({})", res.status()))
        }
    }

    /// Poll the mailbox for `code`'s peer info, tolerating the host not
    /// having registered yet (the two sides don't register/lookup in any
    /// guaranteed order).
    pub async fn lookup(&self, code: &str) -> Result<LookupResponse> {
        let deadline = tokio::time::Instant::now() + LOOKUP_TIMEOUT;
        loop {
            let attempt = self
                .http
                .get(format!("{}/lookup/{code}", self.base_url))
                .send()
                .await;
            match attempt {
                Ok(res) if res.status().is_success() => {
                    let body: LookupResponse = res
                        .json()
                        .await
                        .map_err(|e| anyhow!("mailbox returned a malformed response: {e}"))?;
                    return Ok(body);
                }
                Ok(_) | Err(_) => {
                    if tokio::time::Instant::now() >= deadline {
                        return Err(anyhow!(
                            "no peer found for this code (it may have expired, or the \
                             host hasn't started yet)"
                        ));
                    }
                    tokio::time::sleep(LOOKUP_POLL_INTERVAL).await;
                }
            }
        }
    }

    /// Best-effort cleanup once a code has served its purpose.
    pub async fn unregister(&self, code: &str, token: Option<&str>) {
        let mut req = self
            .http
            .delete(format!("{}/register/{code}", self.base_url));
        if let Some(t) = token {
            req = req.header("Authorization", format!("Bearer {t}"));
        }
        let _ = req.send().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Exercises the real iroh stack end-to-end (hole-punch/relay against
    // n0's public infrastructure), so it needs real network access and
    // takes a few seconds — not run by default, see CI/README. Run with
    // `cargo test -p frostwall --lib internet:: -- --ignored`.
    //
    // The whole exchange is wrapped in an outer deadline (on top of the
    // timeouts already inside `host_endpoint`/`connect_to`/`pair_streams`)
    // so a misbehaving network fails this test loudly within ~2 minutes
    // instead of hanging indefinitely — see the "data channel" timeout
    // added after a manual run got silently killed with no diagnostics.
    #[tokio::test]
    #[ignore = "requires real network access to iroh's relay/discovery infra"]
    async fn host_and_join_exchange_frames_over_iroh() {
        tokio::time::timeout(Duration::from_secs(120), async {
            let host_ep = host_endpoint().await.expect("host endpoint");
            let join_ep = join_endpoint().await.expect("join endpoint");
            let host_id = endpoint_id_string(&host_ep);

            let host_task = tokio::spawn(async move {
                let mut conn = accept_one(&host_ep).await.expect("accept");
                conn.send(b"hello from host").await.expect("send");
                let reply = conn.recv().await.expect("recv");
                assert_eq!(reply, b"hello from joiner");
            });

            // Give the host a moment to be ready to accept before dialing.
            tokio::time::sleep(Duration::from_millis(200)).await;
            let mut joiner_conn = connect_to(&join_ep, &host_id).await.expect("connect");
            let first = joiner_conn.recv().await.expect("recv");
            assert_eq!(first, b"hello from host");
            joiner_conn
                .send(b"hello from joiner")
                .await
                .expect("send");

            host_task.await.expect("host task panicked");
        })
        .await
        .expect("test exceeded its 120s safety deadline — see comment above");
    }

    #[test]
    fn mailbox_base_url_trims_trailing_slash() {
        let mailbox = Mailbox::new("https://mailbox.example.com/");
        assert_eq!(mailbox.base_url, "https://mailbox.example.com");
    }
}
