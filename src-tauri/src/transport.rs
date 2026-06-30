//! Transport: a framed, length-delimited TCP connection. Each logical
//! message on the wire is `4-byte big-endian length || payload`. Encryption
//! is layered on top by the transfer/protocol modules — this is just the
//! reliable byte-pipe plus framing.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use anyhow::{anyhow, Result};
use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::codec::{Framed, LengthDelimitedCodec};

/// Largest single framed message we will accept (1 MiB — comfortably above
/// our 256 KiB encrypted file chunks).
pub const MAX_FRAME: usize = 1 << 20;

/// Bind a TCP listener on a specific interface IP (avoids exposing the
/// listener on every interface / untrusted networks). Port 0 => OS picks.
pub async fn bind_to(ip: IpAddr, port: u16) -> Result<TcpListener> {
    TcpListener::bind((ip, port))
        .await
        .map_err(|e| anyhow!("bind: {e}"))
}

/// Bind on all interfaces (`0.0.0.0`). Used by tests; production binds to
/// the discovered LAN interface via [`bind_to`].
pub async fn bind(port: u16) -> Result<TcpListener> {
    bind_to(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port).await
}

/// Connect to a peer and return a framed connection.
pub async fn connect(addr: SocketAddr) -> Result<Connection> {
    let stream = TcpStream::connect(addr)
        .await
        .map_err(|e| anyhow!("connect: {e}"))?;
    Ok(Connection::from_stream(stream))
}

/// Accept an inbound connection on a listener.
pub async fn accept(listener: &TcpListener) -> Result<Connection> {
    let (stream, _peer) = listener
        .accept()
        .await
        .map_err(|e| anyhow!("accept: {e}"))?;
    Ok(Connection::from_stream(stream))
}

/// A length-delimited TCP connection.
pub struct Connection {
    framed: Framed<TcpStream, LengthDelimitedCodec>,
}

impl Connection {
    fn from_stream(stream: TcpStream) -> Self {
        let codec = LengthDelimitedCodec::builder()
            .max_frame_length(MAX_FRAME)
            .new_codec();
        Connection {
            framed: Framed::new(stream, codec),
        }
    }

    /// Send one framed message.
    pub async fn send(&mut self, bytes: &[u8]) -> Result<()> {
        self.framed
            .send(Bytes::copy_from_slice(bytes))
            .await
            .map_err(|e| anyhow!("send frame: {e}"))
    }

    /// Receive one framed message. Errors if the peer closed the connection.
    pub async fn recv(&mut self) -> Result<Vec<u8>> {
        match self.framed.next().await {
            Some(Ok(b)) => Ok(b.to_vec()),
            Some(Err(e)) => Err(anyhow!("recv frame: {e}")),
            None => Err(anyhow!("connection closed by peer")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
