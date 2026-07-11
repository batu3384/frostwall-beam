//! Transfer engine: streams files/folders over a framed connection as
//! AEAD-encrypted chunks, verifying each file with Blake3. Progress is
//! reported via a callback so the Tauri layer can forward it to the UI.
//!
//! Half-duplex protocol (see `protocol::Message`): sender sends
//! Manifest, then for each file `Chunk*` then `FileEnd(hash)`, then waits
//! for the receiver's `Done`. Receiver verifies every hash before replying.
//!
//! # Receiver trust boundary
//!
//! Every field of the peer-supplied `Manifest` is **untrusted**. The receiver
//! therefore: confines each `rel_path` to the download dir (no traversal),
//! caps the file count and total declared size, bounds the bytes actually
//! written per file to the declared size, and writes to a temp file that is
//! only renamed into place once the Blake3 hash verifies — so a malformed,
//! truncated, or malicious transfer never leaves a partial/corrupt file at
//! the final destination.

use std::collections::HashSet;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::{anyhow, Result};
use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::crypto::{self, SessionKeys};
use crate::protocol::{self, ManifestEntry, Message, CHUNK_SIZE};
use crate::transport::Connection;

/// Hard cap on the number of files in one Manifest (DoS bound).
pub const MAX_FILES: usize = 50_000;
/// Hard cap on total declared transfer size (1 TiB).
pub const MAX_TOTAL: u64 = 1u64 << 40;
/// Max length of a single relative path in the Manifest.
pub const MAX_REL_PATH_LEN: usize = 4096;
/// Max directory recursion depth when collecting a folder.
const MAX_DEPTH: usize = 64;
/// Suffix for the temp file a transfer writes before atomic rename.
const PARTIAL_SUFFIX: &str = ".frostwallpart";

/// Returns `Err` when the user (or peer) cancelled the transfer.
pub fn is_cancelled(err: &anyhow::Error) -> bool {
    err.to_string().contains("transfer cancelled")
}

fn check_cancel(cancel: &AtomicBool) -> Result<()> {
    if cancel.load(Ordering::Relaxed) {
        Err(anyhow!("transfer cancelled"))
    } else {
        Ok(())
    }
}

/// AEAD-wrap a control-plane message (manifest, accept, done, …) for the wire.
pub fn seal_control(keys: &SessionKeys, msg: &Message) -> Result<Vec<u8>> {
    let inner = protocol::encode(msg)?;
    let ct = crypto::encrypt_chunk(&keys.control_key, &inner)?;
    protocol::encode(&Message::Encrypted(ct))
}

/// Unwrap a control-plane message received on the wire.
pub fn open_control(keys: &SessionKeys, frame: &[u8]) -> Result<Message> {
    match protocol::decode(frame)? {
        Message::Encrypted(ct) => {
            let inner = crypto::decrypt_chunk(&keys.control_key, &ct)?;
            protocol::decode(&inner)
        }
        other => Err(anyhow!("expected encrypted control message, got {other:?}")),
    }
}

async fn recv_or_cancel(
    conn: &mut Connection,
    cancel: &AtomicBool,
    keys: &SessionKeys,
) -> Result<Vec<u8>> {
    tokio::select! {
        biased;
        _ = async {
            while !cancel.load(Ordering::Relaxed) {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        } => {
            let _ = conn.send(&seal_control(keys, &Message::Cancel)?).await;
            Err(anyhow!("transfer cancelled"))
        }
        frame = conn.recv() => frame,
    }
}
/// Reject bidi overrides, zero-width, and other control characters in paths.
fn path_has_dangerous_unicode(s: &str) -> bool {
    s.chars().any(|c| {
        let u = c as u32;
        (0x200B..=0x200F).contains(&u)
            || (0x202A..=0x202E).contains(&u)
            || (0x2066..=0x2069).contains(&u)
            || u == 0xFEFF
            || c.is_control()
    })
}

/// Pick a non-colliding destination path when `dest` already exists.
pub fn unique_dest_path(dest: &Path) -> PathBuf {
    if !dest.exists() {
        return dest.to_path_buf();
    }
    let parent = dest.parent().unwrap_or_else(|| Path::new("."));
    let stem = dest
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("file");
    let ext = dest
        .extension()
        .and_then(|s| s.to_str())
        .map(|e| format!(".{e}"))
        .unwrap_or_default();
    for n in 1..=9999 {
        let candidate = parent.join(format!("{stem} ({n}){ext}"));
        if !candidate.exists() {
            return candidate;
        }
    }
    dest.to_path_buf()
}

#[derive(Debug, Clone, Copy)]
pub struct Progress {
    pub transferred: u64,
    pub total: u64,
}

/// One file to send: read from `source`, announce on the wire as `rel_path`.
#[derive(Debug, Clone)]
pub struct SendItem {
    pub source: PathBuf,
    pub rel_path: String,
}

/// Confine an untrusted relative path to `dest_dir`, returning the safe
/// absolute destination. Rejects absolute paths, `..` / `.` / root / prefix
/// components, NUL bytes, backslashes, and empty paths. Because only
/// `Component::Normal` segments are allowed over an absolute base, the result
/// is mathematically guaranteed to stay within `dest_dir`.
pub fn confine_path(dest_dir: &Path, rel: &str) -> Result<PathBuf> {
    if rel.is_empty() || rel.contains('\0') {
        return Err(anyhow!("empty or NUL path in manifest"));
    }
    if rel.len() > MAX_REL_PATH_LEN {
        return Err(anyhow!("path too long in manifest"));
    }
    if rel.contains('\\') {
        return Err(anyhow!("backslash in manifest path"));
    }
    if path_has_dangerous_unicode(rel) {
        return Err(anyhow!("unsafe unicode in manifest path"));
    }
    let p = Path::new(rel);
    if !p.is_relative() {
        return Err(anyhow!("absolute path in manifest: {rel}"));
    }
    if !p.components().all(|c| matches!(c, Component::Normal(_))) {
        return Err(anyhow!("unsafe path component in manifest: {rel}"));
    }
    Ok(dest_dir.join(p))
}

/// Validate an untrusted Manifest: file count, total size, and per-entry
/// path safety. Returns the summed total.
pub fn validate_manifest(entries: &[ManifestEntry]) -> Result<u64> {
    if entries.is_empty() {
        return Err(anyhow!("empty manifest"));
    }
    if entries.len() > MAX_FILES {
        return Err(anyhow!("manifest exceeds {MAX_FILES} files"));
    }
    let mut seen = HashSet::new();
    let mut total: u64 = 0;
    for e in entries {
        if !seen.insert(e.rel_path.clone()) {
            return Err(anyhow!("duplicate path in manifest"));
        }
        // confine_path checks the path is safe; ignore the built dest here.
        confine_path(Path::new("."), &e.rel_path)?;
        total = total
            .checked_add(e.size)
            .ok_or_else(|| anyhow!("manifest size overflow"))?;
    }
    if total > MAX_TOTAL {
        return Err(anyhow!("manifest total exceeds {MAX_TOTAL} bytes"));
    }
    Ok(total)
}

/// Expand a list of roots (files and/or folders) into a flat send list.
/// Symlinks are **never followed** (local-data-exfiltration guard): a symlink
/// root is rejected, and symlinks inside a folder are skipped.
pub fn collect_items(roots: &[PathBuf]) -> Result<Vec<SendItem>> {
    let mut out = Vec::new();
    for root in roots {
        let meta = std::fs::symlink_metadata(root)?;
        if meta.is_symlink() {
            return Err(anyhow!("refusing to send a symlink: {}", root.display()));
        }
        if meta.is_file() {
            let rel = root
                .file_name()
                .ok_or_else(|| anyhow!("invalid file name"))?
                .to_string_lossy()
                .replace('\\', "/");
            out.push(SendItem { source: root.clone(), rel_path: rel });
        } else if meta.is_dir() {
            let base = root.parent().unwrap_or_else(|| Path::new("."));
            let mut seen = HashSet::new();
            walk(root, base, &mut out, 0, &mut seen)?;
        }
    }
    Ok(out)
}

fn walk(
    dir: &Path,
    base: &Path,
    out: &mut Vec<SendItem>,
    depth: usize,
    seen: &mut HashSet<(u64, u64)>,
) -> Result<()> {
    if depth > MAX_DEPTH {
        return Err(anyhow!("max directory depth exceeded"));
    }
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let meta = std::fs::symlink_metadata(&path)?;
        if meta.is_symlink() {
            continue; // never follow symlinks
        }
        if meta.is_dir() {
            // cycle guard on canonicalized inode (best-effort)
            if let Ok(c) = std::fs::canonicalize(&path) {
                if let Ok(s) = std::fs::metadata(&c) {
                    let key = file_key(&s);
                    if !seen.insert(key) {
                        continue;
                    }
                }
            }
            walk(&path, base, out, depth + 1, seen)?;
        } else if meta.is_file() {
            let rel = path
                .strip_prefix(base)
                .map_err(|e| anyhow!("strip prefix: {e}"))?
                .to_string_lossy()
                .replace('\\', "/");
            out.push(SendItem { source: path, rel_path: rel });
        }
    }
    Ok(())
}

#[cfg(unix)]
fn file_key(meta: &std::fs::Metadata) -> (u64, u64) {
    use std::os::unix::fs::MetadataExt;
    (meta.dev(), meta.ino())
}
#[cfg(not(unix))]
fn file_key(_meta: &std::fs::Metadata) -> (u64, u64) {
    (0, 0)
}

/// Send `items` over `conn`, encrypting with `keys`. Calls `on_progress`
/// as bytes are written. Returns Ok only after the receiver replies `Done`.
pub async fn send<F: FnMut(Progress)>(
    conn: &mut Connection,
    keys: &SessionKeys,
    items: &[SendItem],
    on_progress: &mut F,
    cancel: &AtomicBool,
) -> Result<()> {
    check_cancel(cancel)?;
    // Build and send the manifest (stat once, here — not again mid-stream).
    if items.len() > MAX_FILES {
        return Err(anyhow!("transfer exceeds {MAX_FILES} files"));
    }
    let mut entries = Vec::with_capacity(items.len());
    let mut total: u64 = 0;
    for it in items {
        let size = std::fs::metadata(&it.source)?.len();
        total = total
            .checked_add(size)
            .ok_or_else(|| anyhow!("total size overflow"))?;
        entries.push(ManifestEntry { rel_path: it.rel_path.clone(), size });
    }
    conn.send(&seal_control(keys, &Message::Manifest(entries))?).await?;

    // Wait for the receiver to accept before sending encrypted payload.
    let reply = recv_or_cancel(conn, cancel, keys).await?;
    match open_control(keys, &reply)? {
        Message::Accept => {}
        Message::Reject => return Err(anyhow!("transfer rejected by peer")),
        Message::Cancel => return Err(anyhow!("transfer cancelled by peer")),
        other => return Err(anyhow!("expected Accept, got {other:?}")),
    }

    let key = &keys.file_key;
    let mut transferred: u64 = 0;
    for it in items {
        check_cancel(cancel)?;
        let mut file = fs::File::open(&it.source).await?;
        let mut hasher = blake3::Hasher::new();
        let mut buf = vec![0u8; CHUNK_SIZE];
        loop {
            check_cancel(cancel)?;
            let n = file.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            let plaintext = &buf[..n];
            hasher.update(plaintext);
            let ct = crypto::encrypt_chunk(key, plaintext)?;
            conn.send(&protocol::encode(&Message::Chunk(ct))?).await?;
            transferred += n as u64;
            on_progress(Progress { transferred, total });
        }
        let hash = *hasher.finalize().as_bytes();
        conn.send(&seal_control(keys, &Message::FileEnd(hash))?).await?;
    }

    // Wait for the receiver to confirm every hash verified.
    let reply = recv_or_cancel(conn, cancel, keys).await?;
    match open_control(keys, &reply)? {
        Message::Done => Ok(()),
        Message::Cancel => Err(anyhow!("transfer cancelled by peer")),
        other => Err(anyhow!("expected Done, got {other:?}")),
    }
}

/// Receive a transfer into `dest_dir`, decrypting with `keys`. Calls
/// `on_progress` as bytes are written. Replies `Done` only if every file
/// hash matches.
pub async fn recv<F: FnMut(Progress)>(
    conn: &mut Connection,
    keys: &SessionKeys,
    dest_dir: &Path,
    on_progress: &mut F,
    cancel: &AtomicBool,
) -> Result<()> {
    let first = recv_or_cancel(conn, cancel, keys).await?;
    match open_control(keys, &first)? {
        Message::Manifest(ref entries) => {
            validate_manifest(entries)?;
        }
        other => return Err(anyhow!("expected Manifest, got {other:?}")),
    }
    conn.send(&seal_control(keys, &Message::Accept)?).await?;
    recv_from_first(conn, keys, dest_dir, on_progress, first, cancel).await
}

/// Like `recv`, but the first wire frame (the Manifest) has already been read
/// — used by the session coordinator which races incoming frames against local
/// send commands in a `select!`.
pub async fn recv_from_first<F: FnMut(Progress)>(
    conn: &mut Connection,
    keys: &SessionKeys,
    dest_dir: &Path,
    on_progress: &mut F,
    first_frame: Vec<u8>,
    cancel: &AtomicBool,
) -> Result<()> {
    let entries = match open_control(keys, &first_frame)? {
        Message::Manifest(e) => e,
        other => return Err(anyhow!("expected Manifest, got {other:?}")),
    };
    let total = validate_manifest(&entries)?;

    let key = &keys.file_key;
    let mut transferred: u64 = 0;
    for entry in entries {
        check_cancel(cancel)?;
        let dest = unique_dest_path(&confine_path(dest_dir, &entry.rel_path)?);
        let partial = append_suffix(&dest, PARTIAL_SUFFIX);

        // Ensure the destination's parent directory exists before we create
        // the temp file inside it.
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent).await?;
        }

        // Receive one file into the temp path; on ANY error remove the temp
        // so a malformed/truncated/malicious transfer leaves nothing behind.
        let result = recv_one_file(conn, keys, key, &partial, entry.size, total, &mut transferred, on_progress, cancel).await;
        if result.is_err() {
            let _ = fs::remove_file(&partial).await;
            if cancel.load(Ordering::Relaxed) {
                let _ = conn.send(&seal_control(keys, &Message::Cancel)?).await;
            }
            return result;
        }
        // Hash verified -> atomically promote the temp file to the final dest.
        fs::rename(&partial, &dest).await?;
    }

    conn.send(&seal_control(keys, &Message::Done)?).await?;
    Ok(())
}

/// Receive a single file into `partial`, enforcing the declared `size` cap.
/// Verifies the Blake3 hash against the `FileEnd`. Returns Err (without
/// removing the temp — caller handles cleanup) on any failure.
#[allow(clippy::too_many_arguments)]
async fn recv_one_file<F: FnMut(Progress)>(
    conn: &mut Connection,
    keys: &SessionKeys,
    key: &[u8; 32],
    partial: &Path,
    declared_size: u64,
    total: u64,
    transferred: &mut u64,
    on_progress: &mut F,
    cancel: &AtomicBool,
) -> Result<()> {
    let mut file = fs::File::create(partial).await?;
    let mut hasher = blake3::Hasher::new();
    let mut written: u64 = 0;
    loop {
        check_cancel(cancel)?;
        let bytes = recv_or_cancel(conn, cancel, keys).await?;
        let msg = match protocol::decode(&bytes)? {
            Message::Chunk(ct) => Message::Chunk(ct),
            _ => open_control(keys, &bytes)?,
        };
        match msg {
            Message::Chunk(ct) => {
                let pt = crypto::decrypt_chunk(key, &ct)?;
                let new_written = written
                    .checked_add(pt.len() as u64)
                    .ok_or_else(|| anyhow!("file size overflow"))?;
                if new_written > declared_size {
                    return Err(anyhow!(
                        "peer sent more bytes than declared ({} > {})",
                        new_written,
                        declared_size
                    ));
                }
                file.write_all(&pt).await?;
                hasher.update(&pt);
                written = new_written;
                *transferred = transferred
                    .checked_add(pt.len() as u64)
                    .ok_or_else(|| anyhow!("transfer size overflow"))?;
                on_progress(Progress { transferred: *transferred, total });
            }
            Message::FileEnd(expected) => {
                if written != declared_size {
                    return Err(anyhow!(
                        "file size mismatch: expected {declared_size}, got {written}"
                    ));
                }
                let got = *hasher.finalize().as_bytes();
                if got != expected {
                    return Err(anyhow!("integrity check failed"));
                }
                file.flush().await?;
                return Ok(());
            }
            Message::Cancel => return Err(anyhow!("transfer cancelled by peer")),
            other => return Err(anyhow!("unexpected message during file: {other:?}")),
        }
    }
}

fn append_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut s = path.to_string_lossy().into_owned();
    s.push_str(suffix);
    PathBuf::from(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::SessionKeys;
    use crate::transport;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

    fn no_cancel() -> AtomicBool {
        AtomicBool::new(false)
    }
    use tempfile::tempdir;

    async fn loopback_pair() -> (Connection, Connection) {
        let listener = transport::bind(0).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { transport::accept(&listener).await.unwrap() });
        let client = transport::connect(addr).await.unwrap();
        let srv = server.await.unwrap();
        (client, srv)
    }

    // ---- C1: path confinement ----
    #[test]
    fn confine_rejects_traversal_and_absolute() {
        let base = Path::new("/tmp/out");
        assert!(confine_path(base, "../evil").is_err());
        assert!(confine_path(base, "a/../../b").is_err());
        assert!(confine_path(base, "/etc/passwd").is_err());
        assert!(confine_path(base, "").is_err());
        assert!(confine_path(base, "a\0b").is_err());
        assert!(confine_path(base, "a\\b").is_err());
    }

    #[test]
    fn confine_rejects_dangerous_unicode() {
        let base = Path::new("/tmp/out");
        assert!(confine_path(base, "normal.txt").is_ok());
        assert!(confine_path(base, "evil\u{202e}file.txt").is_err());
        assert!(confine_path(base, "zero\u{200b}width.txt").is_err());
    }

    #[test]
    fn unique_dest_path_avoids_collision() {
        let dir = tempdir().unwrap();
        let existing = dir.path().join("doc.txt");
        std::fs::write(&existing, b"x").unwrap();
        let alt = unique_dest_path(&existing);
        assert_ne!(alt, existing);
        assert!(alt.to_string_lossy().contains("(1)"));
        assert!(!alt.exists());
    }

    #[test]
    fn confine_accepts_normal_relative() {
        let base = Path::new("/tmp/out");
        assert_eq!(confine_path(base, "a.txt").unwrap(), Path::new("/tmp/out/a.txt"));
        assert_eq!(
            confine_path(base, "dir/sub/b.txt").unwrap(),
            Path::new("/tmp/out/dir/sub/b.txt")
        );
    }

    // ---- C4: manifest caps ----
    #[test]
    fn validate_manifest_rejects_oversized_and_unsafe() {
        let big: Vec<ManifestEntry> = (0..MAX_FILES + 1)
            .map(|i| ManifestEntry { rel_path: format!("f{i}"), size: 1 })
            .collect();
        assert!(validate_manifest(&big).is_err());

        let trav = vec![ManifestEntry { rel_path: "../x".into(), size: 1 }];
        assert!(validate_manifest(&trav).is_err());

        let huge = vec![ManifestEntry { rel_path: "a".into(), size: MAX_TOTAL + 1 }];
        assert!(validate_manifest(&huge).is_err());

        assert!(validate_manifest(&[]).is_err());
    }

    #[test]
    fn validate_manifest_sums_total() {
        let m = vec![
            ManifestEntry { rel_path: "a".into(), size: 10 },
            ManifestEntry { rel_path: "b/c".into(), size: 4096 },
        ];
        assert_eq!(validate_manifest(&m).unwrap(), 4106);
    }

    // ---- malicious sender helper ----
    struct EvilFile {
        rel: String,
        chunks: Vec<Vec<u8>>,
        hash: Option<[u8; 32]>,        // None => correct hash over plaintext
        declared_size: Option<u64>,    // None => sum of chunk lengths
    }

    async fn evil_send(mut conn: Connection, keys: &SessionKeys, files: Vec<EvilFile>) {
        let entries: Vec<ManifestEntry> = files
            .iter()
            .map(|f| ManifestEntry {
                rel_path: f.rel.clone(),
                size: f.declared_size
                    .unwrap_or_else(|| f.chunks.iter().map(|c| c.len() as u64).sum()),
            })
            .collect();
        conn.send(&seal_control(keys, &Message::Manifest(entries)).unwrap())
            .await
            .unwrap();
        for f in files {
            let mut hasher = blake3::Hasher::new();
            for pt in &f.chunks {
                hasher.update(pt);
                let ct = crypto::encrypt_chunk(&keys.file_key, pt).unwrap();
                conn.send(&protocol::encode(&Message::Chunk(ct)).unwrap()).await.unwrap();
            }
            let hash = f.hash.unwrap_or_else(|| *hasher.finalize().as_bytes());
            conn.send(&seal_control(keys, &Message::FileEnd(hash)).unwrap())
                .await
                .unwrap();
        }
    }

    // ---- C1: traversal rejected end-to-end, nothing written outside dest ----
    #[tokio::test]
    async fn recv_rejects_traversal_manifest() {
        let (a, mut b) = loopback_pair().await;
        let keys = SessionKeys::derive(b"shared");
        let dir = tempdir().unwrap();
        let dest = dir.path().join("out");

        let evil = vec![EvilFile { rel: "../evil.txt".into(), chunks: vec![b"pwn".to_vec()], hash: None, declared_size: None }];
        let keys_a = keys.clone();
        tokio::spawn(async move { evil_send(a, &keys_a, evil).await });

        let cancel = no_cancel();
        let r = recv(&mut b, &keys, &dest, &mut |_| {}, &cancel).await;
        assert!(r.is_err());
        assert!(!dir.path().join("evil.txt").exists());
    }

    // ---- C3: peer exceeding declared size is aborted ----
    #[tokio::test]
    async fn recv_aborts_size_overrun() {
        let (a, mut b) = loopback_pair().await;
        let keys = SessionKeys::derive(b"shared");
        let dir = tempdir().unwrap();
        let dest = dir.path().join("out");

        // declared size 3, but send 5 bytes
        let evil = vec![EvilFile {
            rel: "ok.txt".into(),
            chunks: vec![b"hello".to_vec()],
            hash: None,
            declared_size: Some(3),
        }];
        let keys_a = keys.clone();
        tokio::spawn(async move { evil_send(a, &keys_a, evil).await });

        let cancel = no_cancel();
        let r = recv(&mut b, &keys, &dest, &mut |_| {}, &cancel).await;
        assert!(r.is_err());
        // no final file, no lingering partial
        assert!(!dest.join("ok.txt").exists());
        assert!(!dest.join("ok.txt.frostwallpart").exists());
    }

    // ---- C2: hash mismatch leaves no file at dest and no partial ----
    #[tokio::test]
    async fn recv_cleans_partial_on_hash_mismatch() {
        let (a, mut b) = loopback_pair().await;
        let keys = SessionKeys::derive(b"shared");
        let dir = tempdir().unwrap();
        let dest = dir.path().join("out");

        let wrong_hash = [0xAAu8; 32];
        let evil = vec![EvilFile {
            rel: "bad.txt".into(),
            chunks: vec![b"contents".to_vec()],
            hash: Some(wrong_hash),
            declared_size: None,
        }];
        let keys_a = keys.clone();
        tokio::spawn(async move { evil_send(a, &keys_a, evil).await });

        let cancel = no_cancel();
        let r = recv(&mut b, &keys, &dest, &mut |_| {}, &cancel).await;
        assert!(r.is_err());
        assert!(!dest.join("bad.txt").exists());
        assert!(!dest.join("bad.txt.frostwallpart").exists());
    }

    // ---- C3b: peer sending fewer bytes than declared is rejected ----
    #[tokio::test]
    async fn recv_rejects_undersized_file() {
        let (a, mut b) = loopback_pair().await;
        let keys = SessionKeys::derive(b"shared");
        let dir = tempdir().unwrap();
        let dest = dir.path().join("out");

        let evil = vec![EvilFile {
            rel: "short.txt".into(),
            chunks: vec![b"x".to_vec()],
            hash: None,
            declared_size: Some(100),
        }];
        let keys_a = keys.clone();
        tokio::spawn(async move { evil_send(a, &keys_a, evil).await });

        let cancel = no_cancel();
        let r = recv(&mut b, &keys, &dest, &mut |_| {}, &cancel).await;
        assert!(r.is_err());
        assert!(!dest.join("short.txt").exists());
    }

    // ---- happy path still works + final file present ----
    #[tokio::test]
    async fn send_recv_single_file() {
        let (mut a, mut b) = loopback_pair().await;
        let keys = SessionKeys::derive(b"shared-secret");
        let dir = tempdir().unwrap();
        let src = dir.path().join("hello.txt");
        let content = b"hello world contents".to_vec();
        fs::write(&src, &content).await.unwrap();

        let items = vec![SendItem { source: src, rel_path: "hello.txt".into() }];
        let dest = dir.path().join("out");

        let keys_r = keys.clone();
        let dest_r = dest.clone();
        let cancel = no_cancel();
        let recv_task =
            tokio::spawn(async move { recv(&mut b, &keys_r, &dest_r, &mut |_| {}, &cancel).await });

        send(&mut a, &keys, &items, &mut |_| {}, &no_cancel()).await.unwrap();
        recv_task.await.unwrap().unwrap();

        let got = fs::read(dest.join("hello.txt")).await.unwrap();
        assert_eq!(got, content);
    }

    #[tokio::test]
    async fn send_recv_folder_preserves_structure() {
        let (mut a, mut b) = loopback_pair().await;
        let keys = SessionKeys::derive(b"folder-secret");
        let dir = tempdir().unwrap();
        let src_root = dir.path().join("data");
        fs::create_dir_all(src_root.join("sub")).await.unwrap();
        fs::write(src_root.join("a.txt"), b"aaa").await.unwrap();
        fs::write(src_root.join("sub").join("b.txt"), b"bbbbbbbb").await.unwrap();

        let items = collect_items(&[src_root.clone()]).unwrap();
        let dest = dir.path().join("received");

        let keys_r = keys.clone();
        let dest_r = dest.clone();
        let cancel = no_cancel();
        let recv_task =
            tokio::spawn(async move { recv(&mut b, &keys_r, &dest_r, &mut |_| {}, &cancel).await });

        send(&mut a, &keys, &items, &mut |_| {}, &no_cancel()).await.unwrap();
        recv_task.await.unwrap().unwrap();

        assert_eq!(fs::read(dest.join("data/a.txt")).await.unwrap(), b"aaa");
        assert_eq!(fs::read(dest.join("data/sub/b.txt")).await.unwrap(), b"bbbbbbbb");
    }

    #[tokio::test]
    async fn progress_reports_bytes() {
        let (mut a, mut b) = loopback_pair().await;
        let keys = SessionKeys::derive(b"prog-secret");
        let dir = tempdir().unwrap();
        let src = dir.path().join("big.bin");
        let content = vec![0x11u8; CHUNK_SIZE * 2 + 1234];
        fs::write(&src, &content).await.unwrap();

        let items = vec![SendItem { source: src, rel_path: "big.bin".into() }];
        let dest = dir.path().join("out");

        let keys_r = keys.clone();
        let dest_r = dest.clone();
        let cancel = no_cancel();
        let recv_task =
            tokio::spawn(async move { recv(&mut b, &keys_r, &dest_r, &mut |_| {}, &cancel).await });

        static LAST_PCT: AtomicU64 = AtomicU64::new(0);
        send(&mut a, &keys, &items, &mut |p: Progress| {
            let pct = (p.transferred * 100 / p.total.max(1)) as u64;
            LAST_PCT.store(pct, Ordering::SeqCst);
        }, &no_cancel())
        .await
        .unwrap();
        recv_task.await.unwrap().unwrap();

        assert_eq!(LAST_PCT.load(Ordering::SeqCst), 100);
    }

    // ---- N1: symlinks are skipped / rejected when collecting ----
    #[cfg(unix)]
    #[test]
    fn collect_items_skips_symlinks() {
        use std::os::unix::fs::symlink;
        let dir = tempdir().unwrap();
        let root = dir.path().join("share");
        std::fs::create_dir_all(root.join("sub")).unwrap();
        std::fs::write(root.join("real.txt"), b"x").unwrap();
        // symlink to a sensitive file inside the shared folder — must be skipped
        let secret = dir.path().join("secret.txt");
        std::fs::write(&secret, b"TOPSECRET").unwrap();
        symlink(&secret, root.join("leak")).unwrap();

        let items = collect_items(&[root.clone()]).unwrap();
        let rels: Vec<String> = items.iter().map(|i| i.rel_path.clone()).collect();
        assert!(rels.iter().any(|r| r == "share/real.txt"));
        assert!(!rels.iter().any(|r| r.contains("leak")));
    }

    #[cfg(unix)]
    #[test]
    fn collect_items_rejects_symlink_root() {
        use std::os::unix::fs::symlink;
        let dir = tempdir().unwrap();
        let target = dir.path().join("real");
        std::fs::create_dir_all(&target).unwrap();
        let link = dir.path().join("link");
        symlink(&target, &link).unwrap();
        assert!(collect_items(&[link]).is_err());
    }

    #[test]
    fn collect_items_file_and_folder() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("single.txt");
        std::fs::write(&file, b"x").unwrap();
        let folder = dir.path().join("f");
        std::fs::create_dir_all(folder.join("nested")).unwrap();
        std::fs::write(folder.join("one.txt"), b"1").unwrap();
        std::fs::write(folder.join("nested").join("two.txt"), b"2").unwrap();

        let items = collect_items(&[file.clone(), folder.clone()]).unwrap();
        let rels: Vec<&str> = items.iter().map(|i| i.rel_path.as_str()).collect();
        assert!(rels.contains(&"single.txt"));
        assert!(rels.contains(&"f/one.txt"));
        assert!(rels.contains(&"f/nested/two.txt"));
    }
}
