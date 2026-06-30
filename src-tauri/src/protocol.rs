//! Wire protocol: length-delimited frames (see `transport`) whose payloads are
//! `<version byte> || bincode-encoded Message`. File chunks are already
//! AEAD-encrypted by the transfer layer before being wrapped in `Message::Chunk`.
//!
//! The leading version byte lets a future format change reject an incompatible
//! peer with a clear error instead of silently misparsing. Deserialization is
//! size-limited so a malformed frame cannot drive an unbounded allocation.

use anyhow::{anyhow, Result};
use bincode::Options;
use serde::{Deserialize, Serialize};

/// Plaintext chunk size read from disk before encryption.
pub const CHUNK_SIZE: usize = 256 * 1024;

/// Current wire-format version. Bump on an incompatible change.
const WIRE_VERSION: u8 = 1;

/// Cap passed to the bincode deserializer (matches the transport MAX_FRAME).
/// Defends against any code path that decodes untrusted bytes without the
/// length-delimited codec's frame cap.
const DECODE_LIMIT: u64 = 1 << 20;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ManifestEntry {
    /// Path relative to the transfer root (e.g. "docs/notes.txt").
    pub rel_path: String,
    pub size: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum Message {
    /// First message: the ordered list of files about to be sent.
    Manifest(Vec<ManifestEntry>),
    /// One encrypted chunk: `nonce || ciphertext+tag`.
    Chunk(Vec<u8>),
    /// Marks the end of a file and carries the Blake3 hash of its plaintext,
    /// so the receiver can verify integrity.
    FileEnd([u8; 32]),
    /// Receiver -> sender: every file received and hash-verified.
    Done,
    /// Receiver -> sender: user accepted the incoming manifest; chunks may follow.
    Accept,
    /// Receiver -> sender: user declined the incoming transfer.
    Reject,
    /// Either side: abort the in-flight transfer without tearing down the session.
    Cancel,
}

/// Encode a message to `<version byte> || bincode(body)`.
pub fn encode(msg: &Message) -> Result<Vec<u8>> {
    let body = bincode::options()
        .with_limit(DECODE_LIMIT)
        .serialize(msg)
        .map_err(|e| anyhow!("encode message: {e}"))?;
    let mut out = Vec::with_capacity(1 + body.len());
    out.push(WIRE_VERSION);
    out.extend_from_slice(&body);
    Ok(out)
}

/// Decode a message from `<version byte> || bincode(body)`. Rejects frames
/// with an unknown version and applies a size limit on deserialization.
pub fn decode(bytes: &[u8]) -> Result<Message> {
    if bytes.len() < 2 {
        return Err(anyhow!("frame too short for a versioned message"));
    }
    let (ver, body) = (bytes[0], &bytes[1..]);
    if ver != WIRE_VERSION {
        return Err(anyhow!(
            "incompatible wire version: got {ver}, expected {WIRE_VERSION}"
        ));
    }
    bincode::options()
        .with_limit(DECODE_LIMIT)
        .deserialize(body)
        .map_err(|e| anyhow!("decode message: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_round_trips() {
        let m = Message::Manifest(vec![
            ManifestEntry { rel_path: "a.txt".into(), size: 10 },
            ManifestEntry { rel_path: "dir/b.bin".into(), size: 4096 },
        ]);
        assert_eq!(decode(&encode(&m).unwrap()).unwrap(), m);
    }

    #[test]
    fn chunk_round_trips_with_large_payload() {
        let m = Message::Chunk(vec![0x77u8; 300_000]);
        assert_eq!(decode(&encode(&m).unwrap()).unwrap(), m);
    }

    #[test]
    fn file_end_and_done_round_trip() {
        let hash = [0xAAu8; 32];
        assert_eq!(decode(&encode(&Message::FileEnd(hash)).unwrap()).unwrap(), Message::FileEnd(hash));
        assert_eq!(decode(&encode(&Message::Done).unwrap()).unwrap(), Message::Done);
    }

    #[test]
    fn accept_reject_and_cancel_round_trip() {
        assert_eq!(decode(&encode(&Message::Accept).unwrap()).unwrap(), Message::Accept);
        assert_eq!(decode(&encode(&Message::Reject).unwrap()).unwrap(), Message::Reject);
        assert_eq!(decode(&encode(&Message::Cancel).unwrap()).unwrap(), Message::Cancel);
    }

    #[test]
    fn decode_garbage_errors() {
        assert!(decode(&[0xFFu8; 8]).is_err());
    }

    #[test]
    fn encode_prepends_version_byte() {
        let encoded = encode(&Message::Done).unwrap();
        assert_eq!(encoded[0], WIRE_VERSION);
    }

    #[test]
    fn decode_rejects_unknown_version() {
        let mut bad = encode(&Message::Done).unwrap();
        bad[0] = 99;
        assert!(decode(&bad).is_err());
    }

    #[test]
    fn decode_rejects_short_frame() {
        assert!(decode(&[WIRE_VERSION]).is_err()); // version + no body
        assert!(decode(&[]).is_err());
    }
}
