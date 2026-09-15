//! Transport: a framed, length-delimited connection. Each logical message
//! on the wire is `4-byte big-endian length || payload`. Encryption is
//! layered on top by the transfer/protocol modules — this is just the
//! reliable byte-pipe plus framing.
//!
//! [`Connection`] is transport-agnostic: it wraps anything that is an
//! `AsyncRead + AsyncWrite` byte stream behind one boxed trait object, so
//! the same handshake/transfer code in `session.rs`/`transfer.rs` works
//! whether the underlying pipe is a plain LAN TCP socket ([`connect`] /
//! [`accept`]) or an iroh QUIC stream pair for internet sessions (see
//! `internet.rs`, which builds a `Connection` via [`Connection::from_io`]).

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use anyhow::{anyhow, Result};
use bytes::Bytes;
use futures::{FutureExt, SinkExt, StreamExt};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::codec::{Framed, LengthDelimitedCodec};

/// Largest single framed message we will accept (8 MiB). File chunks are
/// 256 KiB; a 50_000-file Manifest with short/medium paths must still fit
/// after AEAD wrapping. Pathological 4 KiB names are rejected by the
/// transfer layer before this cap is used as a DoS bound.
pub const MAX_FRAME: usize = 8 << 20;
/// LAN TCP connect bound. A stale mDNS address must not hang Join forever.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Lockstep `transfer::is_pipe_dead`.
pub const CLOSED_BY_PEER: &str = "connection closed by peer";
pub const SEND_FRAME_PREFIX: &str = "send frame:";
pub const RECV_FRAME_PREFIX: &str = "recv frame:";

/// Anything that can back a [`Connection`]: a duplex byte stream.
pub trait Duplex: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Duplex for T {}

/// Bind a TCP listener on a specific interface IP (avoids exposing the
/// listener on every interface / untrusted networks). Port 0 => OS picks.
pub async fn bind_to(ip: IpAddr, port: u16) -> Result<TcpListener> {
    TcpListener::bind((ip, port))
        .await
        .map_err(|e| anyhow!("bind: {e}"))
}

/// Bind on loopback. Tests only; production uses [`bind_to`] on the LAN IP.
/// Windows `connect(0.0.0.0:port)` fails with WSAEADDRNOTAVAIL (10049).
pub async fn bind(port: u16) -> Result<TcpListener> {
    bind_to(IpAddr::V4(Ipv4Addr::LOCALHOST), port).await
}

/// Connect to a peer over LAN TCP and return a framed connection.
pub async fn connect(addr: SocketAddr) -> Result<Connection> {
    connect_within(addr, CONNECT_TIMEOUT).await
}

async fn connect_within(addr: SocketAddr, limit: Duration) -> Result<Connection> {
    let stream = tokio::time::timeout(limit, TcpStream::connect(addr))
        .await
        .map_err(|_| anyhow!("timed out connecting to the peer"))?
        .map_err(|e| anyhow!("connect: {e}"))?;
    let _ = stream.set_nodelay(true);
    Ok(Connection::from_io(stream))
}

/// Accept an inbound LAN TCP connection on a listener.
pub async fn accept(listener: &TcpListener) -> Result<Connection> {
    let (stream, _peer) = listener
        .accept()
        .await
        .map_err(|e| anyhow!("accept: {e}"))?;
    let _ = stream.set_nodelay(true);
    Ok(Connection::from_io(stream))
}

/// A length-delimited connection over any duplex byte stream.
pub struct Connection {
    framed: Framed<Box<dyn Duplex>, LengthDelimitedCodec>,
}

impl Connection {
    /// Wrap any `AsyncRead + AsyncWrite` stream (TCP, or an iroh stream pair
    /// joined via `tokio::io::join`) into a framed [`Connection`].
    pub fn from_io<IO: Duplex + 'static>(io: IO) -> Self {
        let codec = LengthDelimitedCodec::builder()
            .max_frame_length(MAX_FRAME)
            .new_codec();
        Connection {
            framed: Framed::new(Box::new(io), codec),
        }
    }

    /// Send one framed message.
    pub async fn send(&mut self, bytes: &[u8]) -> Result<()> {
        self.framed
            .send(Bytes::copy_from_slice(bytes))
            .await
            .map_err(|e| anyhow!("{SEND_FRAME_PREFIX} {e}"))
    }

    /// Receive one framed message. Errors if the peer closed the connection.
    pub async fn recv(&mut self) -> Result<Vec<u8>> {
        match self.framed.next().await {
            Some(Ok(b)) => Ok(b.to_vec()),
            Some(Err(e)) => Err(anyhow!("{RECV_FRAME_PREFIX} {e}")),
            None => Err(anyhow!(CLOSED_BY_PEER)),
        }
    }

    /// Non-blocking poll: `Ok(Some)` if a complete frame is already buffered,
    /// `Ok(None)` if the peer has not sent one yet. Does not cancel an
    /// in-flight send. Used so a payload loop can notice `Cancel` after each
    /// chunk without splitting the framed codec.
    pub fn try_recv(&mut self) -> Result<Option<Vec<u8>>> {
        match self.framed.next().now_or_never() {
            None => Ok(None),
            Some(Some(Ok(b))) => Ok(Some(b.to_vec())),
            Some(Some(Err(e))) => Err(anyhow!("{RECV_FRAME_PREFIX} {e}")),
            Some(None) => Err(anyhow!(CLOSED_BY_PEER)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn bind_local_addr_is_loopback() {
        let listener = bind(0).await.unwrap();
        let addr = listener.local_addr().unwrap();
        assert!(addr.ip().is_loopback(), "{addr}");
        let mut client = connect(addr).await.unwrap();
        let mut server = accept(&listener).await.unwrap();
        client.send(b"ping").await.unwrap();
        assert_eq!(server.recv().await.unwrap(), b"ping");
    }

    #[tokio::test]
    async fn send_recv_roundtrip() {
        let listener = bind(0).await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let mut conn = accept(&listener).await.unwrap();
            let a = conn.recv().await.unwrap();
            let b = conn.recv().await.unwrap();
            conn.send(b"ack").await.unwrap();
            (a, b)
        });

        let mut client = connect(addr).await.unwrap();
        client.send(b"hello").await.unwrap();
        client.send(b"world").await.unwrap();
        let ack = client.recv().await.unwrap();

        let (a, b) = server.await.unwrap();
        assert_eq!(a, b"hello");
        assert_eq!(b, b"world");
        assert_eq!(ack, b"ack");
    }

    #[tokio::test]
    async fn large_frame_roundtrips() {
        let listener = bind(0).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let payload = vec![0x5Au8; 300_000];

        let payload_clone = payload.clone();
        let server = tokio::spawn(async move {
            let mut conn = accept(&listener).await.unwrap();
            conn.recv().await.unwrap()
        });

        let mut client = connect(addr).await.unwrap();
        client.send(&payload_clone).await.unwrap();
        let got = server.await.unwrap();
        assert_eq!(got, payload);
    }

    #[tokio::test]
    async fn recv_on_closed_errors() {
        let listener = bind(0).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut client = connect(addr).await.unwrap();
        let server = accept(&listener).await.unwrap();
        drop(server);
        let r = client.recv().await;
        assert!(r.is_err());
    }

    #[tokio::test]
    async fn try_recv_empty_then_frame() {
        let listener = bind(0).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut client = connect(addr).await.unwrap();
        let mut server = accept(&listener).await.unwrap();
        assert_eq!(client.try_recv().unwrap(), None);
        server.send(b"ping").await.unwrap();
        let got = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if let Some(b) = client.try_recv().unwrap() {
                    return b;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("frame must become readable");
        assert_eq!(got, b"ping");
    }

    #[tokio::test]
    async fn connect_does_not_hang_on_blackhole() {
        // TEST-NET-1 is documentation space; typically no RST. Must fail fast.
        let addr = "192.0.2.1:1".parse().unwrap();
        let t0 = tokio::time::Instant::now();
        let err = match connect_within(addr, Duration::from_millis(400)).await {
            Ok(_) => panic!("blackhole connect must not succeed"),
            Err(e) => e,
        };
        let msg = err.to_string();
        assert!(
            msg.contains("timed out") || msg.contains("connect"),
            "{msg}"
        );
        assert!(
            t0.elapsed() < Duration::from_secs(3),
            "LAN connect must be bounded, elapsed={:?}",
            t0.elapsed()
        );
    }
}
