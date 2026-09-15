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
//! never follows symlinks when creating parent dirs or the temp file, caps
//! the file count and total declared size, bounds the bytes actually written
//! per file to the declared size, and writes to a temp file that is only
//! renamed into place once the Blake3 hash verifies — so a malformed,
//! truncated, or malicious transfer never leaves a partial/corrupt file at
//! the final destination. Hash-ok files are `fsync`'d before rename. Stale
//! `*.frostwallpart` leftovers from a crash are swept at the start of recv.

use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::{anyhow, Result};
use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::crypto::{self, SessionKeys};
use crate::protocol::{self, ManifestEntry, Message, CHUNK_SIZE};
use crate::transport::{self, Connection};

/// Hard cap on the number of files in one Manifest (DoS bound).
pub const MAX_FILES: usize = 50_000;
/// Hard cap on total declared transfer size (1 TiB).
pub const MAX_TOTAL: u64 = 1u64 << 40;
/// Max length of a single relative path in the Manifest.
pub const MAX_REL_PATH_LEN: usize = 4096;
/// Max directory recursion depth when collecting a folder.
const MAX_DEPTH: usize = 64;
/// Crash leftovers (`*.frostwallpart`) under dest. Bound so a dest pointed
/// at a huge tree cannot stall recv.
/// ponytail: O(dest tree) up to this visit cap; upgrade: track in-flight
/// partials only.
const SWEEP_VISIT_MAX: usize = 4096;
/// How long the sender waits for Accept/Reject after sending a Manifest.
/// Same window as `commands::DECISION_TIMEOUT`: SAS confirm + file-list review.
const ACCEPT_REPLY_TIMEOUT: Duration = Duration::from_secs(6 * 60);
/// After the last `FileEnd`, wait this long for `Done`. Unbounded wait left
/// the sender stuck at 100% when the peer errored without a readable Cancel
/// (silent NAT/iroh drop). Receiver verify+promote is local and short.
const DONE_REPLY_TIMEOUT: Duration = Duration::from_secs(60);
/// Per-frame cap while reading payload. A silent NAT/iroh drop used to hang
/// `recv` forever. 5 min still allows a slow 256 KiB relay chunk (~1 KB/s).
const PAYLOAD_STALL_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const PAYLOAD_STALL_MSG: &str = "timed out waiting for payload";
pub const COLLISION_MSG: &str = "peer started a transfer at the same time";
/// Suffix for the temp file a transfer writes before atomic rename.
const PARTIAL_SUFFIX: &str = ".frostwallpart";

/// Returns `true` when the user (or peer) cancelled the transfer.
pub fn is_cancelled(err: &anyhow::Error) -> bool {
    err.to_string().contains("transfer cancelled")
}

/// Wire is gone or wedged. Coordinator must drop the session: drain-and-
/// continue would desync the next Manifest (`Framed` mid-send / silent NAT).
pub fn is_pipe_dead(err: &anyhow::Error) -> bool {
    let s = err.to_string();
    s == crate::transport::CLOSED_BY_PEER
        || s.starts_with(crate::transport::RECV_FRAME_PREFIX)
        || s.starts_with(crate::transport::SEND_FRAME_PREFIX)
        || s.contains(PAYLOAD_STALL_MSG)
}

/// Both sides sent (or one side saw a Manifest while collecting).
pub fn is_collision(err: &anyhow::Error) -> bool {
    err.to_string().contains(COLLISION_MSG)
}

/// Leftover payload frames. Coordinator no longer drains — idle `recv`
/// ignores Chunk/FileEnd/control noise and waits for the next Manifest.
/// Kept so `transfer::send`/`recv` tests can clear a pipe between runs.
pub fn needs_abort_drain(err: &anyhow::Error) -> bool {
    if is_pipe_dead(err) || is_collision(err) {
        return false;
    }
    let s = err.to_string();
    if s.contains("transfer rejected by peer")
        || s.contains("timed out waiting for the peer to accept")
        || s.contains("wanted Accept")
        || s.contains("nothing to send")
        || s.contains("integrity check failed")
    {
        return false;
    }
    true
}

/// Local `cancel_transfer` only. Peer abort still matches [`is_cancelled`] so
/// we do not echo another Cancel frame; the coordinator still surfaces it.
pub fn is_local_cancel(err: &anyhow::Error) -> bool {
    let s = err.to_string();
    s.contains("transfer cancelled") && !s.contains("by peer")
}

/// Payload the receiver could not verify. Not a user cancel — the sender
/// must not show "peer stopped the transfer".
fn is_integrity_fail(err: &anyhow::Error) -> bool {
    let s = err.to_string();
    s.contains("integrity check failed")
        || s.contains("file size mismatch")
        || s.contains("peer sent more bytes")
        || s.contains("aead decryption failed")
        || s.contains("ciphertext shorter than nonce")
        || s.contains("peer sent data for a directory")
}

/// What the receiver puts on the wire after `recv` fails. `None` = already
/// signalled (`Cancel` from [`abort_if_cancelled`] / [`recv_or_cancel`]) or
/// the peer sent `Cancel` first.
fn recv_fail_signal(err: &anyhow::Error) -> Option<Message> {
    if is_integrity_fail(err) {
        Some(Message::Reject)
    } else if is_cancelled(err) || is_pipe_dead(err) {
        None
    } else {
        Some(Message::Cancel)
    }
}

/// Drop leftover frames after an aborted `send`/`recv` test so the next
/// direct call is not confused by in-flight chunks. Production coordinator
/// skips this: idle swallows stray frames instead of eating a retry Manifest.
pub async fn drain_after_abort(conn: &mut Connection) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        let now = tokio::time::Instant::now();
        if now >= deadline {
            return;
        }
        let slice = (deadline - now).min(Duration::from_millis(200));
        match tokio::time::timeout(slice, conn.recv()).await {
            Ok(Ok(_)) => continue,
            _ => return,
        }
    }
}

/// Live-session send with the payload stall cap. Timeout cancels the in-flight
/// `Framed` write — caller must drop the pipe (`is_pipe_dead`), not continue.
pub(crate) async fn send_or_stall(conn: &mut Connection, bytes: &[u8]) -> Result<()> {
    match tokio::time::timeout(PAYLOAD_STALL_TIMEOUT, conn.send(bytes)).await {
        Ok(r) => r,
        Err(_) => Err(anyhow!(PAYLOAD_STALL_MSG)),
    }
}

async fn send_cancel_frame(conn: &mut Connection, keys: &SessionKeys) -> Result<()> {
    send_or_stall(conn, &seal_control(keys, &Message::Cancel)?).await
}

/// Cancel echo failed in a way that desyncs the pipe — drop the session.
fn cancel_err(send: Result<()>) -> anyhow::Error {
    match send {
        Err(e) if is_pipe_dead(&e) => e,
        _ => anyhow!("transfer cancelled"),
    }
}

fn check_cancel(cancel: &AtomicBool) -> Result<()> {
    if cancel.load(Ordering::Relaxed) {
        Err(anyhow!("transfer cancelled"))
    } else {
        Ok(())
    }
}

async fn abort_if_cancelled(
    conn: &mut Connection,
    keys: &SessionKeys,
    cancel: &AtomicBool,
) -> Result<()> {
    if cancel.load(Ordering::Relaxed) {
        return Err(cancel_err(send_cancel_frame(conn, keys).await));
    }
    Ok(())
}

/// Send one frame, then notice a peer abort already in the read buffer.
/// A long payload must not keep blasting after the receiver aborted.
///
/// `Done` can race in after the last `FileEnd` on a fast path (tiny file,
/// loopback). That is success, not "unexpected control".
///
/// Stall timeout discards this send future. Caller must tear the session
/// down (`is_pipe_dead`) — do not keep using the `Framed` pipe.
async fn send_live(
    conn: &mut Connection,
    keys: &SessionKeys,
    cancel: &AtomicBool,
    bytes: &[u8],
) -> Result<Option<Message>> {
    abort_if_cancelled(conn, keys, cancel).await?;
    send_or_stall(conn, bytes).await?;
    match conn.try_recv()? {
        None => Ok(None),
        Some(frame) => match open_control(keys, &frame) {
            Ok(Message::Cancel) => Err(anyhow!("transfer cancelled by peer")),
            Ok(Message::Reject) => Err(anyhow!("integrity check failed")),
            Ok(msg) => Ok(Some(msg)),
            Err(e) => Err(e),
        },
    }
}

fn expect_quiet_while_sending(hit: Option<Message>) -> Result<()> {
    match hit {
        None => Ok(()),
        Some(_) => Err(anyhow!("unexpected control message during send")),
    }
}

/// AEAD-wrap a control-plane message (manifest, accept, done, …) for the wire.
pub fn seal_control(keys: &SessionKeys, msg: &Message) -> Result<Vec<u8>> {
    let inner = protocol::encode(msg)?;
    let ct = crypto::encrypt_chunk(&keys.control_key, &inner)?;
    protocol::encode(&Message::Encrypted(ct))
}

/// Poly1305 tag length (ciphertext is plaintext + this).
const AEAD_TAG_LEN: usize = 16;

/// Encrypted control-frame length for `msg` (no RNG). Must match [`seal_control`].
fn sealed_control_len(msg: &Message) -> Result<usize> {
    let inner = protocol::encode(msg)?;
    let packed = crypto::NONCE_LEN + inner.len() + AEAD_TAG_LEN;
    Ok(protocol::encode(&Message::Encrypted(vec![0u8; packed]))?.len())
}

fn ensure_control_fits(msg: &Message) -> Result<()> {
    match sealed_control_len(msg) {
        Ok(n) if n <= transport::MAX_FRAME => Ok(()),
        _ => Err(anyhow!("transfer list too large")),
    }
}

fn ensure_manifest_fits(items: &[SendItem]) -> Result<()> {
    if items.is_empty() {
        return Ok(());
    }
    let man = Message::Manifest(
        items
            .iter()
            .map(|i| ManifestEntry {
                rel_path: i.rel_path.clone(),
                size: i.size,
            })
            .collect(),
    );
    ensure_control_fits(&man)
}

/// Unwrap a control-plane message received on the wire.
pub fn open_control(keys: &SessionKeys, frame: &[u8]) -> Result<Message> {
    match protocol::decode(frame)? {
        Message::Encrypted(ct) => {
            let inner = crypto::decrypt_chunk(&keys.control_key, &ct)?;
            protocol::decode(&inner)
        }
        _ => Err(anyhow!("expected encrypted control message")),
    }
}

/// Each side sends its device name after SPAKE2, then waits briefly for the
/// peer's. Timeout / non-Hello → `Ok(None)` (peer too old / no name). A dead
/// pipe is `Err` so we do not emit paired on a closed connection.
const HELLO_TIMEOUT: Duration = Duration::from_secs(10);

pub async fn exchange_hello(
    conn: &mut Connection,
    keys: &SessionKeys,
    local_name: Option<&str>,
) -> Result<Option<String>> {
    let ours = protocol::sanitize_display_name(local_name).unwrap_or_default();
    let frame = seal_control(keys, &Message::Hello(ours))?;
    match tokio::time::timeout(HELLO_TIMEOUT, conn.send(&frame)).await {
        Err(_) => return Err(anyhow!("handshake timed out (peer stalled)")),
        Ok(Err(e)) => return Err(e),
        Ok(Ok(())) => {}
    }
    match tokio::time::timeout(HELLO_TIMEOUT, conn.recv()).await {
        Err(_) => Ok(None),
        Ok(Err(e)) => Err(e),
        Ok(Ok(frame)) => match open_control(keys, &frame) {
            Ok(Message::Hello(n)) => Ok(protocol::sanitize_display_name(Some(&n))),
            _ => Ok(None),
        },
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
        } => Err(cancel_err(send_cancel_frame(conn, keys).await)),
        frame = conn.recv() => frame,
    }
}

async fn recv_or_cancel_within(
    conn: &mut Connection,
    cancel: &AtomicBool,
    keys: &SessionKeys,
    limit: Duration,
    timeout_msg: &'static str,
) -> Result<Vec<u8>> {
    match tokio::time::timeout(limit, recv_or_cancel(conn, cancel, keys)).await {
        Ok(r) => r,
        Err(_) => {
            if let Err(e) = send_cancel_frame(conn, keys).await {
                if is_pipe_dead(&e) {
                    return Err(e);
                }
            }
            Err(anyhow!("{timeout_msg}"))
        }
    }
}

async fn recv_payload_frame(
    conn: &mut Connection,
    cancel: &AtomicBool,
    keys: &SessionKeys,
) -> Result<Vec<u8>> {
    recv_or_cancel_within(conn, cancel, keys, PAYLOAD_STALL_TIMEOUT, PAYLOAD_STALL_MSG).await
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

/// Pick a non-colliding destination path when `dest` is already occupied
/// (file, dir, or dangling symlink). Never returns an existing path.
pub fn unique_dest_path(dest: &Path) -> Result<PathBuf> {
    if !path_occupied(dest) {
        return Ok(dest.to_path_buf());
    }
    let parent = dest.parent().unwrap_or_else(|| Path::new("."));
    let stem = dest
        .file_stem()
        .map(OsString::from)
        .unwrap_or_else(|| OsString::from("file"));
    let ext = dest.extension().map(OsString::from);
    for n in 1..=9999 {
        let mut name = stem.clone();
        name.push(format!(" ({n})"));
        if let Some(e) = &ext {
            name.push(".");
            name.push(e);
        }
        let candidate = parent.join(&name);
        if !path_occupied(&candidate) {
            return Ok(candidate);
        }
    }
    Err(anyhow!("could not allocate a unique destination path"))
}

fn path_occupied(p: &Path) -> bool {
    std::fs::symlink_metadata(p).is_ok()
}

/// Real directory (not a symlink or Windows junction). A dest-dir child like
/// `photos → /etc` must not be reused as a Manifest prefix.
fn is_real_dir(p: &Path) -> bool {
    std::fs::symlink_metadata(p)
        .map(|m| m.is_dir() && !is_link_like(p, &m))
        .unwrap_or(false)
}

/// Symlink, or a Windows junction / WSL link. Cloud placeholders keep the
/// reparse bit but must still be writable dest dirs (OneDrive).
pub fn is_link_like_path(p: &Path) -> bool {
    std::fs::symlink_metadata(p)
        .map(|m| is_link_like(p, &m))
        .unwrap_or(false)
}

fn is_link_like(path: &Path, meta: &std::fs::Metadata) -> bool {
    if meta.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        windows_symlink_or_junction(path, meta)
    }
    #[cfg(not(windows))]
    {
        let _ = path;
        false
    }
}

#[cfg(windows)]
fn windows_symlink_or_junction(path: &Path, meta: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    if meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0 {
        return false;
    }
    match windows_reparse_tag(path) {
        Some(tag) => {
            const IO_REPARSE_TAG_MOUNT_POINT: u32 = 0xA000_0003;
            const IO_REPARSE_TAG_SYMLINK: u32 = 0xA000_000C;
            const IO_REPARSE_TAG_LX_SYMLINK: u32 = 0xA000_001D;
            tag == IO_REPARSE_TAG_MOUNT_POINT
                || tag == IO_REPARSE_TAG_SYMLINK
                || tag == IO_REPARSE_TAG_LX_SYMLINK
        }
        // Unreadable reparse: fail closed so a junction is never followed.
        None => true,
    }
}

/// Reparse tag of `path` itself (does not follow). `None` if not a reparse
/// or the handle cannot be opened.
#[cfg(windows)]
fn windows_reparse_tag(path: &Path) -> Option<u32> {
    use std::os::windows::ffi::OsStrExt;
    let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
    wide.push(0);
    extern "system" {
        fn CreateFileW(
            name: *const u16,
            access: u32,
            share: u32,
            sa: *const core::ffi::c_void,
            disp: u32,
            flags: u32,
            template: *mut core::ffi::c_void,
        ) -> *mut core::ffi::c_void;
        fn DeviceIoControl(
            handle: *mut core::ffi::c_void,
            code: u32,
            in_buf: *const core::ffi::c_void,
            in_len: u32,
            out_buf: *mut core::ffi::c_void,
            out_len: u32,
            returned: *mut u32,
            overlapped: *mut core::ffi::c_void,
        ) -> i32;
        fn CloseHandle(handle: *mut core::ffi::c_void) -> i32;
    }
    const GENERIC_READ: u32 = 0x8000_0000;
    const FILE_SHARE_READ: u32 = 0x1;
    const FILE_SHARE_WRITE: u32 = 0x2;
    const FILE_SHARE_DELETE: u32 = 0x4;
    const OPEN_EXISTING: u32 = 3;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const FSCTL_GET_REPARSE_POINT: u32 = 0x0009_00A8;
    const INVALID: isize = -1;
    unsafe {
        let h = CreateFileW(
            wide.as_ptr(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            core::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            core::ptr::null_mut(),
        );
        if h.is_null() || h as isize == INVALID {
            return None;
        }
        let mut buf = [0u8; 16 * 1024];
        let mut ret = 0u32;
        let ok = DeviceIoControl(
            h,
            FSCTL_GET_REPARSE_POINT,
            core::ptr::null(),
            0,
            buf.as_mut_ptr().cast(),
            buf.len() as u32,
            &mut ret,
            core::ptr::null_mut(),
        );
        CloseHandle(h);
        if ok == 0 || ret < 4 {
            return None;
        }
        Some(u32::from_le_bytes(buf[0..4].try_into().ok()?))
    }
}

/// Map a confined dest path around names that already exist as a file or
/// symlink. `photos/a.txt` + dest file `photos` becomes `photos (1)/a.txt`
/// for every entry under that prefix in this transfer.
fn remap_dest(
    dest_dir: &Path,
    confined: &Path,
    remap: &mut HashMap<PathBuf, PathBuf>,
) -> Result<PathBuf> {
    let rel = confined
        .strip_prefix(dest_dir)
        .map_err(|_| anyhow!("refusing to write through a symlink"))?;
    let mut logical = PathBuf::new();
    let mut actual = dest_dir.to_path_buf();
    let comps: Vec<_> = rel
        .components()
        .map(|c| match c {
            Component::Normal(n) => Ok(n.to_os_string()),
            _ => Err(anyhow!("unsafe path component in dest")),
        })
        .collect::<Result<Vec<_>>>()?;
    if comps.is_empty() {
        return Err(anyhow!("unsafe path component in dest"));
    }
    let n = comps.len();
    for (i, name) in comps.iter().enumerate() {
        logical.push(name);
        if let Some(mapped) = remap.get(&logical) {
            actual = mapped.clone();
            continue;
        }
        let candidate = actual.join(name);
        let last = i + 1 == n;
        if !last && is_real_dir(&candidate) {
            actual = candidate;
            continue;
        }
        if path_occupied(&candidate) {
            let uniq = unique_dest_path(&candidate)?;
            remap.insert(logical.clone(), uniq.clone());
            actual = uniq;
        } else {
            actual = candidate;
        }
    }
    Ok(actual)
}

/// Install `partial` at `dest` without replacing a name that appeared after
/// [`unique_dest_path`]. Unix `rename` otherwise clobbers.
fn promote_partial(partial: &Path, dest: &Path) -> Result<()> {
    let original = dest.to_path_buf();
    let mut dest = unique_dest_path(&original)?;
    for _ in 0..32 {
        match rename_noreplace(partial, &dest) {
            Ok(()) => {
                fsync_parent(&dest);
                return Ok(());
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                dest = unique_dest_path(&original)?;
            }
            Err(e) => return Err(e.into()),
        }
    }
    Err(anyhow!("could not allocate a unique destination"))
}

fn rename_noreplace(from: &Path, to: &Path) -> std::io::Result<()> {
    #[cfg(target_os = "macos")]
    {
        const RENAME_EXCL: libc::c_uint = 0x0004;
        let from_c = cstr(from)?;
        let to_c = cstr(to)?;
        let rc = unsafe { libc::renamex_np(from_c.as_ptr(), to_c.as_ptr(), RENAME_EXCL) };
        if rc == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }
    #[cfg(target_os = "linux")]
    {
        const RENAME_NOREPLACE: libc::c_uint = 1;
        let from_c = cstr(from)?;
        let to_c = cstr(to)?;
        let rc = unsafe {
            libc::renameat2(
                libc::AT_FDCWD,
                from_c.as_ptr(),
                libc::AT_FDCWD,
                to_c.as_ptr(),
                RENAME_NOREPLACE,
            )
        };
        if rc == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }
    #[cfg(windows)]
    {
        // std::fs::rename replaces an existing `to` on Windows. Promote must
        // not clobber a file that appeared after unique_dest_path.
        use std::os::windows::ffi::OsStrExt;
        fn wide(p: &Path) -> Vec<u16> {
            p.as_os_str().encode_wide().chain(Some(0)).collect()
        }
        extern "system" {
            fn MoveFileExW(existing: *const u16, new: *const u16, flags: u32) -> i32;
        }
        const MOVEFILE_WRITE_THROUGH: u32 = 0x8;
        let from_w = wide(from);
        let to_w = wide(to);
        let rc = unsafe { MoveFileExW(from_w.as_ptr(), to_w.as_ptr(), MOVEFILE_WRITE_THROUGH) };
        if rc != 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
    {
        if path_occupied(to) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "destination exists",
            ));
        }
        std::fs::rename(from, to)
    }
}

fn fsync_parent(path: &Path) {
    if let Some(dir) = path.parent() {
        if let Ok(f) = std::fs::File::open(dir) {
            let _ = f.sync_all();
        }
    }
}

fn is_stale_partial(path: &Path) -> bool {
    let Some(name) = path.file_name() else {
        return false;
    };
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        name.as_bytes().ends_with(PARTIAL_SUFFIX.as_bytes())
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        let needle: Vec<u16> = PARTIAL_SUFFIX.encode_utf16().collect();
        let wide: Vec<u16> = name.encode_wide().collect();
        wide.ends_with(&needle)
    }
    #[cfg(not(any(unix, windows)))]
    {
        name.to_str().is_some_and(|n| n.ends_with(PARTIAL_SUFFIX))
    }
}

fn sweep_stale_partials(root: &Path) {
    let mut visits = 0usize;
    let _ = sweep_stale_partials_walk(root, 0, &mut visits);
}

fn sweep_stale_partials_walk(dir: &Path, depth: usize, visits: &mut usize) -> Result<()> {
    if depth > MAX_DEPTH || *visits >= SWEEP_VISIT_MAX {
        return Ok(());
    }
    let rd = match std::fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(_) => return Ok(()),
    };
    for ent in rd {
        if *visits >= SWEEP_VISIT_MAX {
            break;
        }
        let ent = match ent {
            Ok(e) => e,
            Err(_) => continue,
        };
        *visits += 1;
        let path = ent.path();
        let meta = match std::fs::symlink_metadata(&path) {
            Ok(m) => m,
            Err(_) => continue,
        };
        if is_link_like(&path, &meta) {
            continue;
        }
        if meta.is_dir() {
            let _ = sweep_stale_partials_walk(&path, depth + 1, visits);
        } else if meta.is_file() && is_stale_partial(&path) {
            let _ = std::fs::remove_file(&path);
        }
    }
    Ok(())
}

#[cfg(unix)]
fn cstr(p: &Path) -> std::io::Result<std::ffi::CString> {
    use std::os::unix::ffi::OsStrExt;
    std::ffi::CString::new(p.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "path contains NUL"))
}

/// True if any component of `p` is a symlink or Windows junction.
/// `symlink_metadata` only inspects the final name, so `link/out` with
/// `link → /etc` looks like a real directory after the parent is followed.
/// Leading OS aliases (`/var` → `/private/var` on macOS) are skipped so a
/// dest under `/var/folders` still works.
pub fn path_has_symlink_component(p: &Path) -> bool {
    let mut acc = PathBuf::new();
    for c in p.components() {
        acc.push(c);
        if is_link_like_path(&acc) && !os_path_alias(&acc) {
            return true;
        }
    }
    false
}

/// Volume/compat aliases the kernel follows for well-known prefixes.
/// User-planted names (`innocent → ~/.ssh`) are not in this set.
fn os_path_alias(p: &Path) -> bool {
    matches!(
        p.to_str(),
        Some("/var") | Some("/tmp") | Some("/etc") | Some("/bin") | Some("/sbin") | Some("/lib") | Some("/lib64")
    )
}

/// Create `target` (and missing parents) under `dest_dir` without following
/// a symlink. `create_dir_all` follows, so a dest-dir child like `leak → /etc`
/// plus Manifest `leak/passwd` would write outside the download folder.
async fn mkdir_nofollow(dest_dir: &Path, target: &Path) -> Result<()> {
    mkdir_abs_nofollow(dest_dir)?;
    if target == dest_dir {
        return Ok(());
    }
    let rel = target
        .strip_prefix(dest_dir)
        .map_err(|_| anyhow!("refusing to write through a symlink"))?;
    let mut cur = dest_dir.to_path_buf();
    for comp in rel.components() {
        match comp {
            Component::Normal(name) => cur.push(name),
            _ => return Err(anyhow!("unsafe path component in dest")),
        }
        match std::fs::symlink_metadata(&cur) {
            Ok(m) if is_link_like(&cur, &m) => {
                return Err(anyhow!("refusing to write through a symlink"));
            }
            Ok(m) if m.is_dir() => {}
            Ok(_) => return Err(anyhow!("path component is not a directory")),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir(&cur).await?;
            }
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

/// Create `path` itself without following a symlink in any prefix.
pub(crate) fn mkdir_abs_nofollow(path: &Path) -> Result<()> {
    let mut cur = PathBuf::new();
    for comp in path.components() {
        cur.push(comp);
        match std::fs::symlink_metadata(&cur) {
            Ok(m) if is_link_like(&cur, &m) => {
                if os_path_alias(&cur) {
                    continue;
                }
                return Err(anyhow!("refusing to write through a symlink"));
            }
            Ok(m) if m.is_dir() => {}
            Ok(_) => return Err(anyhow!("path is not a directory")),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                std::fs::create_dir(&cur)?;
            }
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

fn create_nofollow_file(path: &mut PathBuf) -> Result<fs::File> {
    for _ in 0..32 {
        match try_create_nofollow_new(path) {
            Ok(f) => return Ok(f),
            Err(e) if io_already_exists(&e) => {
                *path = unique_dest_path(path)?;
            }
            Err(e) => return Err(e),
        }
    }
    Err(anyhow!("could not allocate a unique destination path"))
}

fn io_already_exists(err: &anyhow::Error) -> bool {
    err.chain().any(|c| {
        c.downcast_ref::<std::io::Error>()
            .is_some_and(|io| io.kind() == std::io::ErrorKind::AlreadyExists)
    })
}

fn try_create_nofollow_new(path: &Path) -> Result<fs::File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
        {
            Ok(f) => Ok(fs::File::from_std(f)),
            Err(e)
                if e.raw_os_error() == Some(libc::ELOOP)
                    || e.raw_os_error() == Some(libc::EMLINK) =>
            {
                Err(anyhow!("refusing to write through a symlink"))
            }
            Err(e) => Err(e.into()),
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        if is_link_like_path(path) {
            return Err(anyhow!("refusing to write through a symlink"));
        }
        let f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)?;
        if is_link_like(path, &f.metadata()?) {
            return Err(anyhow!("refusing to write through a symlink"));
        }
        Ok(fs::File::from_std(f))
    }
    #[cfg(not(any(unix, windows)))]
    {
        if is_link_like_path(path) {
            return Err(anyhow!("refusing to write through a symlink"));
        }
        Ok(fs::File::from_std(
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path)?,
        ))
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Progress {
    pub transferred: u64,
    pub total: u64,
}

/// One file or empty directory to send. `size` is recorded at collect time
/// (no extra stat on the coordinator). Directories use a trailing `/` and
/// `size == 0` on the wire so old peers still decode the Manifest.
#[derive(Debug, Clone)]
pub struct SendItem {
    pub source: PathBuf,
    pub rel_path: String,
    pub size: u64,
    pub is_dir: bool,
}

impl SendItem {
    /// Stat `source` without following a symlink.
    pub fn from_file(source: PathBuf, rel_path: impl Into<String>) -> Result<Self> {
        let meta = std::fs::symlink_metadata(&source)?;
        if is_link_like(&source, &meta) {
            return Err(anyhow!("refusing to send a symlink: {}", source.display()));
        }
        if !meta.is_file() {
            return Err(anyhow!("not a regular file: {}", source.display()));
        }
        Ok(Self {
            source,
            rel_path: rel_path.into(),
            size: meta.len(),
            is_dir: false,
        })
    }
}

fn is_dir_entry(rel: &str, size: u64) -> Result<bool> {
    if rel.ends_with('/') {
        if size != 0 {
            return Err(anyhow!("directory entry must have size 0"));
        }
        Ok(true)
    } else {
        Ok(false)
    }
}

fn confine_entry(dest_dir: &Path, rel: &str) -> Result<PathBuf> {
    let rel = rel.trim_end_matches('/');
    confine_path(dest_dir, rel)
}

fn empty_blake3() -> [u8; 32] {
    *blake3::hash(b"").as_bytes()
}

/// Confine an untrusted relative path to `dest_dir`, returning the safe
/// absolute destination. Rejects absolute paths, `..` / `.` / root / prefix
/// components, NUL bytes, backslashes, empty paths, and Windows device names
/// (`CON`, `NUL`, `COM1`, …) so a Manifest cannot open a device on the
/// receiver. Because only `Component::Normal` segments are allowed over an
/// absolute base, the result is mathematically guaranteed to stay within
/// `dest_dir`.
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
    if rel.contains(':') {
        return Err(anyhow!("unsafe path component in manifest: {rel}"));
    }
    if path_has_dangerous_unicode(rel) {
        return Err(anyhow!("unsafe unicode in manifest path"));
    }
    let p = Path::new(rel);
    if !p.is_relative() {
        return Err(anyhow!("absolute path in manifest: {rel}"));
    }
    for c in p.components() {
        let Component::Normal(name) = c else {
            return Err(anyhow!("unsafe path component in manifest: {rel}"));
        };
        let Some(s) = name.to_str() else {
            return Err(anyhow!("unsafe path component in manifest: {rel}"));
        };
        if windows_device_name(s) {
            return Err(anyhow!("unsafe path component in manifest: {rel}"));
        }
    }
    let out = dest_dir.join(p);
    if abs_dest_too_long(dest_dir, &out) {
        return Err(anyhow!("path too long in manifest"));
    }
    Ok(out)
}

/// `dest_dir` is the real download folder only when it is absolute (recv).
/// Manifest validation uses `.` and must not apply the OS cap there.
fn abs_dest_too_long(dest_dir: &Path, out: &Path) -> bool {
    if !dest_dir.is_absolute() {
        return false;
    }
    // Room for `.frostwallpart` and unique ` (9999)` on the last component.
    const SLACK: usize = 32;
    out.as_os_str().len().saturating_add(SLACK) > abs_path_cap()
}

fn abs_path_cap() -> usize {
    #[cfg(windows)]
    {
        259
    }
    #[cfg(target_os = "macos")]
    {
        1024
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        4096
    }
}

/// Windows device names (any OS — the receiver may be Windows).
fn windows_device_name(component: &str) -> bool {
    let trimmed = component.trim_end_matches([' ', '.']);
    // Trailing dots/spaces are stripped on Windows (`foo.` → `foo`).
    if trimmed.is_empty() || trimmed != component {
        return true;
    }
    let stem = trimmed.split('.').next().unwrap_or(trimmed);
    matches!(
        stem.to_ascii_uppercase().as_str(),
        "CON"
            | "PRN"
            | "AUX"
            | "NUL"
            | "COM1"
            | "COM2"
            | "COM3"
            | "COM4"
            | "COM5"
            | "COM6"
            | "COM7"
            | "COM8"
            | "COM9"
            | "LPT1"
            | "LPT2"
            | "LPT3"
            | "LPT4"
            | "LPT5"
            | "LPT6"
            | "LPT7"
            | "LPT8"
            | "LPT9"
            | "CONIN$"
            | "CONOUT$"
    )
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
        let ident = e.rel_path.trim_end_matches('/');
        if ident.is_empty() {
            return Err(anyhow!("empty or NUL path in manifest"));
        }
        if !seen.insert(ident.to_string()) {
            return Err(anyhow!("duplicate path in manifest"));
        }
        let _dir = is_dir_entry(&e.rel_path, e.size)?;
        confine_entry(Path::new("."), &e.rel_path)?;
        total = total
            .checked_add(e.size)
            .ok_or_else(|| anyhow!("manifest size overflow"))?;
    }
    if total > MAX_TOTAL {
        return Err(anyhow!("manifest total exceeds {MAX_TOTAL} bytes"));
    }
    Ok(total)
}

/// Real download dir + each Manifest path (Windows MAX_PATH, etc.).
/// Call after [`validate_manifest`] once `dest` is the absolute save folder.
pub fn manifest_fits_dest(dest: &Path, entries: &[ManifestEntry]) -> Result<()> {
    for e in entries {
        confine_path(dest, &e.rel_path)?;
    }
    Ok(())
}

/// Expand a list of roots (files and/or folders) into a flat send list.
/// Symlinks are **never followed** (local-data-exfiltration guard): a symlink
/// root is rejected, and symlinks inside a folder are skipped.
pub fn collect_items(roots: &[PathBuf]) -> Result<Vec<SendItem>> {
    collect_items_cancellable(roots, &AtomicBool::new(false))
}

/// Like [`collect_items`], but returns `transfer cancelled` when `cancel` is set.
pub fn collect_items_cancellable(
    roots: &[PathBuf],
    cancel: &AtomicBool,
) -> Result<Vec<SendItem>> {
    check_cancel(cancel)?;
    let mut out = Vec::new();
    let mut total = 0u64;
    for root in roots {
        check_cancel(cancel)?;
        let meta = std::fs::symlink_metadata(root)?;
        if is_link_like(root, &meta) {
            return Err(anyhow!("refusing to send a symlink: {}", root.display()));
        }
        if meta.is_file() {
            let rel = rel_utf8(root, None)?;
            push_send_item(&mut out, &mut total, root.clone(), rel, meta.len(), false)?;
        } else if meta.is_dir() {
            let base = root.parent().unwrap_or_else(|| Path::new("."));
            let mut seen = HashSet::<PathBuf>::new();
            walk(root, base, &mut out, &mut total, 0, &mut seen, cancel)?;
        }
    }
    ensure_manifest_fits(&out)?;
    Ok(out)
}

fn push_send_item(
    out: &mut Vec<SendItem>,
    total: &mut u64,
    source: PathBuf,
    rel_path: String,
    size: u64,
    is_dir: bool,
) -> Result<()> {
    if out.len() >= MAX_FILES {
        return Err(anyhow!("transfer exceeds {MAX_FILES} files"));
    }
    *total = total
        .checked_add(size)
        .ok_or_else(|| anyhow!("total size overflow"))?;
    if *total > MAX_TOTAL {
        return Err(anyhow!("manifest total exceeds {MAX_TOTAL} bytes"));
    }
    out.push(SendItem {
        source,
        rel_path,
        size,
        is_dir,
    });
    Ok(())
}

fn walk(
    dir: &Path,
    base: &Path,
    out: &mut Vec<SendItem>,
    total: &mut u64,
    depth: usize,
    seen: &mut HashSet<PathBuf>,
    cancel: &AtomicBool,
) -> Result<bool> {
    check_cancel(cancel)?;
    if depth > MAX_DEPTH {
        return Err(anyhow!("max directory depth exceeded"));
    }
    let mut added = false;
    for entry in std::fs::read_dir(dir)? {
        check_cancel(cancel)?;
        let entry = entry?;
        let path = entry.path();
        let meta = std::fs::symlink_metadata(&path)?;
        if is_link_like(&path, &meta) {
            continue; // never follow symlinks / junctions
        }
        if meta.is_dir() {
            // Cycle guard: canonical path, not (dev,ino). Windows MetadataExt
            // is absent so a (0,0) key would skip every sibling directory.
            if let Ok(c) = std::fs::canonicalize(&path) {
                if !seen.insert(c) {
                    continue;
                }
            }
            if walk(&path, base, out, total, depth + 1, seen, cancel)? {
                added = true;
            }
        } else if meta.is_file() {
            let rel = rel_utf8(&path, Some(base))?;
            push_send_item(out, total, path, rel, meta.len(), false)?;
            added = true;
        }
    }
    if !added {
        let mut rel = rel_utf8(dir, Some(base))?;
        if !rel.ends_with('/') {
            rel.push('/');
        }
        push_send_item(out, total, dir.to_path_buf(), rel, 0, true)?;
        added = true;
    }
    Ok(added)
}

/// Wire paths are UTF-8. Lossy names can collide two files onto one Manifest
/// entry and a Windows receiver cannot recreate the OsString.
fn rel_utf8(path: &Path, base: Option<&Path>) -> Result<String> {
    let rel = match base {
        Some(b) => path
            .strip_prefix(b)
            .map_err(|e| anyhow!("strip prefix: {e}"))?,
        None => Path::new(
            path.file_name()
                .ok_or_else(|| anyhow!("invalid file name"))?,
        ),
    };
    let s = rel.to_str().ok_or_else(|| anyhow!("invalid file name"))?;
    Ok(s.replace('\\', "/"))
}

/// Open `path` for send without following a symlink (TOCTOU vs collect).
fn open_send_file(path: &Path, expected: u64, rel: &str) -> Result<std::fs::File> {
    let file = open_nofollow(path)?;
    let meta = file.metadata()?;
    if !meta.is_file() {
        return Err(anyhow!("not a regular file: {rel}"));
    }
    if meta.len() != expected {
        return Err(anyhow!("file changed during send: {rel}"));
    }
    Ok(file)
}

fn open_nofollow(path: &Path) -> Result<std::fs::File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        match std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
        {
            Ok(f) => Ok(f),
            Err(e)
                if e.raw_os_error() == Some(libc::ELOOP)
                    || e.raw_os_error() == Some(libc::EMLINK) =>
            {
                Err(anyhow!("refusing to send a symlink: {}", path.display()))
            }
            Err(e) => Err(e.into()),
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        let f = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)?;
        if is_link_like(path, &f.metadata()?) {
            return Err(anyhow!("refusing to send a symlink: {}", path.display()));
        }
        Ok(f)
    }
    #[cfg(not(any(unix, windows)))]
    {
        if is_link_like_path(path) {
            return Err(anyhow!("refusing to send a symlink: {}", path.display()));
        }
        Ok(std::fs::File::open(path)?)
    }
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
    if items.is_empty() {
        return Err(anyhow!("nothing to send"));
    }
    // Manifest uses collect-time sizes — no 50k-file stat on the coordinator.
    if items.len() > MAX_FILES {
        return Err(anyhow!("transfer exceeds {MAX_FILES} files"));
    }
    let mut entries = Vec::with_capacity(items.len());
    let mut total: u64 = 0;
    for it in items {
        total = total
            .checked_add(it.size)
            .ok_or_else(|| anyhow!("total size overflow"))?;
        entries.push(ManifestEntry {
            rel_path: it.rel_path.clone(),
            size: it.size,
        });
    }
    if total > MAX_TOTAL {
        return Err(anyhow!("manifest total exceeds {MAX_TOTAL} bytes"));
    }
    let man = Message::Manifest(entries);
    ensure_control_fits(&man)?;
    send_or_stall(conn, &seal_control(keys, &man)?).await?;

    // Wait for the receiver to accept before sending encrypted payload.
    let reply = recv_or_cancel_within(
        conn,
        cancel,
        keys,
        ACCEPT_REPLY_TIMEOUT,
        "timed out waiting for the peer to accept",
    )
    .await?;
    match open_control(keys, &reply)? {
        Message::Accept => {}
        Message::Reject => return Err(anyhow!("transfer rejected by peer")),
        Message::Cancel => return Err(anyhow!("transfer cancelled by peer")),
        Message::Manifest(_) => {
            return Err(anyhow!(COLLISION_MSG))
        }
        _ => return Err(anyhow!("unexpected control message (wanted Accept)")),
    }

    match send_payload(conn, keys, items, total, on_progress, cancel).await {
        Ok(()) => Ok(()),
        Err(e) => {
            if !is_cancelled(&e) && !is_integrity_fail(&e) && !is_pipe_dead(&e) {
                if let Err(ce) = send_cancel_frame(conn, keys).await {
                    if is_pipe_dead(&ce) {
                        return Err(ce);
                    }
                }
            }
            Err(e)
        }
    }
}

async fn send_payload<F: FnMut(Progress)>(
    conn: &mut Connection,
    keys: &SessionKeys,
    items: &[SendItem],
    total: u64,
    on_progress: &mut F,
    cancel: &AtomicBool,
) -> Result<()> {
    let key = &keys.file_key;
    let mut transferred: u64 = 0;
    // Leave the "waiting for accept" UI as soon as the peer says Accept —
    // empty dirs / 0-byte files never emit a chunk tick.
    on_progress(Progress { transferred: 0, total });
    let last = items.len().saturating_sub(1);
    for (i, it) in items.iter().enumerate() {
        abort_if_cancelled(conn, keys, cancel).await?;
        if it.is_dir {
            let hit = send_live(
                conn,
                keys,
                cancel,
                &seal_control(keys, &Message::FileEnd(empty_blake3()))?,
            )
            .await?;
            if i == last {
                match hit {
                    None => {}
                    Some(Message::Done) => return Ok(()),
                    Some(_) => {
                        return Err(anyhow!("unexpected control message during send"));
                    }
                }
            } else {
                expect_quiet_while_sending(hit)?;
            }
            continue;
        }
        let mut file = fs::File::from_std(open_send_file(&it.source, it.size, &it.rel_path)?);
        let mut hasher = blake3::Hasher::new();
        let mut buf = vec![0u8; CHUNK_SIZE];
        let mut left = it.size;
        loop {
            if left == 0 {
                break;
            }
            let want = buf.len().min(left as usize);
            let n = file.read(&mut buf[..want]).await?;
            if n == 0 {
                return Err(anyhow!("file changed during send: {}", it.rel_path));
            }
            left -= n as u64;
            let plaintext = &buf[..n];
            hasher.update(plaintext);
            let ct = crypto::encrypt_chunk(key, plaintext)?;
            expect_quiet_while_sending(
                send_live(conn, keys, cancel, &protocol::encode(&Message::Chunk(ct))?)
                    .await?,
            )?;
            transferred += n as u64;
            on_progress(Progress { transferred, total });
        }
        let hash = *hasher.finalize().as_bytes();
        let hit = send_live(
            conn,
            keys,
            cancel,
            &seal_control(keys, &Message::FileEnd(hash))?,
        )
        .await?;
        if i == last {
            match hit {
                None => {}
                Some(Message::Done) => return Ok(()),
                Some(_) => {
                    return Err(anyhow!("unexpected control message during send"));
                }
            }
        } else {
            expect_quiet_while_sending(hit)?;
        }
    }

    let reply = recv_or_cancel_within(
        conn,
        cancel,
        keys,
        DONE_REPLY_TIMEOUT,
        "timed out waiting for the peer to finish",
    )
    .await?;
    match open_control(keys, &reply)? {
        Message::Done => Ok(()),
        Message::Cancel => Err(anyhow!("transfer cancelled by peer")),
        Message::Reject => Err(anyhow!("integrity check failed")),
        _ => Err(anyhow!("unexpected control message (wanted Done)")),
    }
}

/// Receive a transfer into `dest_dir`, decrypting with `keys`. Calls
/// `on_progress` as bytes are written. Replies `Done` only if every file
/// hash matches.
///
/// Auto-sends `Accept` (no UI gate). Production coordinator uses
/// [`recv_from_first`] after the user accepts the pending manifest.
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
        _ => return Err(anyhow!("unexpected control message (wanted Manifest)")),
    }
    send_or_stall(conn, &seal_control(keys, &Message::Accept)?).await?;
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
    let result = recv_from_first_body(conn, keys, dest_dir, on_progress, first_frame, cancel).await;
    if let Err(e) = &result {
        if let Some(msg) = recv_fail_signal(e) {
            if let Ok(frame) = seal_control(keys, &msg) {
                if let Err(se) = send_or_stall(conn, &frame).await {
                    if is_pipe_dead(&se) {
                        return Err(se);
                    }
                }
            }
        }
    }
    result
}

async fn recv_from_first_body<F: FnMut(Progress)>(
    conn: &mut Connection,
    keys: &SessionKeys,
    dest_dir: &Path,
    on_progress: &mut F,
    first_frame: Vec<u8>,
    cancel: &AtomicBool,
) -> Result<()> {
    let entries = match open_control(keys, &first_frame)? {
        Message::Manifest(e) => e,
        _ => return Err(anyhow!("unexpected control message (wanted Manifest)")),
    };
    let total = validate_manifest(&entries)?;
    sweep_stale_partials(dest_dir);

    let key = &keys.file_key;
    let mut transferred: u64 = 0;
    let mut remap = HashMap::new();
    on_progress(Progress { transferred: 0, total });
    for entry in entries {
        abort_if_cancelled(conn, keys, cancel).await?;
        if is_dir_entry(&entry.rel_path, entry.size)? {
            let dest = remap_dest(dest_dir, &confine_entry(dest_dir, &entry.rel_path)?, &mut remap)?;
            mkdir_nofollow(dest_dir, &dest).await?;
            recv_dir_end(conn, keys, cancel).await?;
            continue;
        }
        let dest = remap_dest(dest_dir, &confine_path(dest_dir, &entry.rel_path)?, &mut remap)?;
        let mut partial = append_suffix(&dest, PARTIAL_SUFFIX);

        if let Some(parent) = dest.parent() {
            mkdir_nofollow(dest_dir, parent).await?;
        }

        // Receive one file into the temp path; on ANY error remove the temp
        // so a malformed/truncated/malicious transfer never leaves a partial.
        let result = recv_one_file(conn, keys, key, &mut partial, entry.size, total, &mut transferred, on_progress, cancel).await;
        if result.is_err() {
            let _ = fs::remove_file(&partial).await;
            return result;
        }
        if let Err(e) = promote_partial(&partial, &dest) {
            let _ = fs::remove_file(&partial).await;
            return Err(e);
        }
    }

    send_or_stall(conn, &seal_control(keys, &Message::Done)?).await?;
    Ok(())
}

async fn recv_dir_end(
    conn: &mut Connection,
    keys: &SessionKeys,
    cancel: &AtomicBool,
) -> Result<()> {
    let bytes = recv_payload_frame(conn, cancel, keys).await?;
    let msg = match protocol::decode(&bytes)? {
        Message::Chunk(ct) => Message::Chunk(ct),
        _ => open_control(keys, &bytes)?,
    };
    match msg {
        Message::FileEnd(expected) => {
            if expected != empty_blake3() {
                return Err(anyhow!("integrity check failed"));
            }
            Ok(())
        }
        Message::Cancel => Err(anyhow!("transfer cancelled by peer")),
        Message::Chunk(_) => Err(anyhow!("peer sent data for a directory")),
        _ => Err(anyhow!("unexpected control message during file")),
    }
}

/// Receive a single file into `partial`, enforcing the declared `size` cap.
/// Verifies the Blake3 hash against the `FileEnd`. Returns Err (without
/// removing the temp — caller handles cleanup) on any failure.
#[allow(clippy::too_many_arguments)]
async fn recv_one_file<F: FnMut(Progress)>(
    conn: &mut Connection,
    keys: &SessionKeys,
    key: &[u8; 32],
    partial: &mut PathBuf,
    declared_size: u64,
    total: u64,
    transferred: &mut u64,
    on_progress: &mut F,
    cancel: &AtomicBool,
) -> Result<()> {
    let mut file = create_nofollow_file(partial)?;
    let mut hasher = blake3::Hasher::new();
    let mut written: u64 = 0;
    loop {
        abort_if_cancelled(conn, keys, cancel).await?;
        let bytes = recv_payload_frame(conn, cancel, keys).await?;
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
                file.sync_all().await?;
                drop(file);
                return Ok(());
            }
            Message::Cancel => return Err(anyhow!("transfer cancelled by peer")),
            _ => return Err(anyhow!("unexpected control message during file")),
        }
    }
}

fn append_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut os = path.as_os_str().to_os_string();
    os.push(suffix);
    PathBuf::from(os)
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
    fn item(source: PathBuf, rel: &str) -> SendItem {
        SendItem::from_file(source, rel).expect("send item")
    }
    use tempfile::tempdir;

    #[test]
    fn local_cancel_excludes_peer_abort() {
        let local = anyhow!("transfer cancelled");
        let peer = anyhow!("transfer cancelled by peer");
        assert!(is_cancelled(&local) && is_local_cancel(&local));
        assert!(is_cancelled(&peer) && !is_local_cancel(&peer));
    }

    #[test]
    fn recv_fail_signal_reject_on_integrity_not_cancel() {
        assert_eq!(
            recv_fail_signal(&anyhow!("integrity check failed")),
            Some(Message::Reject)
        );
        assert_eq!(
            recv_fail_signal(&anyhow!("file size mismatch: expected 3, got 1")),
            Some(Message::Reject)
        );
        assert_eq!(recv_fail_signal(&anyhow!("transfer cancelled")), None);
        assert_eq!(
            recv_fail_signal(&anyhow!("transfer cancelled by peer")),
            None
        );
        assert_eq!(
            recv_fail_signal(&anyhow!("unexpected control message during file")),
            Some(Message::Cancel)
        );
        assert_eq!(recv_fail_signal(&anyhow!(PAYLOAD_STALL_MSG)), None);
        assert_eq!(recv_fail_signal(&anyhow!(crate::transport::CLOSED_BY_PEER)), None);
        assert_eq!(recv_fail_signal(&anyhow!("send frame: broken pipe")), None);
        assert!(!is_integrity_fail(&anyhow!("transfer cancelled by peer")));
    }

    #[test]
    fn pipe_dead_is_io_or_stall_not_cancel() {
        assert!(is_pipe_dead(&anyhow!(crate::transport::CLOSED_BY_PEER)));
        assert!(is_pipe_dead(&anyhow!("recv frame: eof")));
        assert!(is_pipe_dead(&anyhow!("send frame: broken pipe")));
        assert!(is_pipe_dead(&anyhow!(PAYLOAD_STALL_MSG)));
        assert!(!is_pipe_dead(&anyhow!("transfer cancelled")));
        assert!(!is_pipe_dead(&anyhow!("integrity check failed")));
        assert!(!is_pipe_dead(&anyhow!("transfer rejected by peer")));
        assert!(is_collision(&anyhow!(COLLISION_MSG)));
        assert!(!is_collision(&anyhow!("transfer rejected by peer")));
        assert!(!is_collision(&anyhow!(PAYLOAD_STALL_MSG)));
        assert!(!needs_abort_drain(&anyhow!(COLLISION_MSG)));
        assert!(!needs_abort_drain(&anyhow!("transfer rejected by peer")));
        assert!(!needs_abort_drain(&anyhow!(
            "timed out waiting for the peer to accept"
        )));
        assert!(!needs_abort_drain(&anyhow!(
            "unexpected control message (wanted Accept)"
        )));
        assert!(!needs_abort_drain(&anyhow!("nothing to send")));
        assert!(!needs_abort_drain(&anyhow!(PAYLOAD_STALL_MSG)));
        assert!(!needs_abort_drain(&anyhow!("integrity check failed")));
        assert!(needs_abort_drain(&anyhow!("transfer cancelled")));
        assert!(needs_abort_drain(&anyhow!("file changed during send")));
        assert!(needs_abort_drain(&anyhow!(
            "timed out waiting for the peer to finish"
        )));
    }

    #[test]
    fn expect_quiet_while_sending_rejects_any_control() {
        assert!(expect_quiet_while_sending(None).is_ok());
        assert!(expect_quiet_while_sending(Some(Message::Done)).is_err());
        assert!(expect_quiet_while_sending(Some(Message::Cancel)).is_err());
    }

    async fn loopback_pair() -> (Connection, Connection) {
        let listener = transport::bind(0).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { transport::accept(&listener).await.unwrap() });
        let client = transport::connect(addr).await.unwrap();
        let srv = server.await.unwrap();
        (client, srv)
    }

    #[tokio::test]
    async fn done_wait_times_out_if_peer_silent() {
        let (mut a, _b) = loopback_pair().await;
        let keys = SessionKeys::derive(b"done-to");
        let t0 = tokio::time::Instant::now();
        let err = recv_or_cancel_within(
            &mut a,
            &no_cancel(),
            &keys,
            Duration::from_millis(80),
            "timed out waiting for the peer to finish",
        )
        .await
        .expect_err("silent peer must not block Done wait");
        assert!(
            err.to_string().contains("timed out waiting for the peer to finish"),
            "{err}"
        );
        assert!(
            t0.elapsed() < Duration::from_secs(2),
            "Done wait must be bounded, elapsed={:?}",
            t0.elapsed()
        );
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
    fn confine_rejects_windows_device_names() {
        let base = Path::new("/tmp/out");
        assert!(confine_path(base, "CON").is_err());
        assert!(confine_path(base, "nul.txt").is_err());
        assert!(confine_path(base, "aux.txt").is_err());
        assert!(confine_path(base, "folder/COM1/x").is_err());
        assert!(confine_path(base, "lpt9.log").is_err());
        assert!(confine_path(base, "CONIN$").is_err());
        assert!(confine_path(base, "conout$.txt").is_err());
        assert!(confine_path(base, "foo.").is_err());
        assert!(confine_path(base, "notes:ads").is_err());
        assert!(confine_path(base, "notes.txt").is_ok());
        assert!(confine_path(base, "console.txt").is_ok());
    }

    #[test]
    fn confine_rejects_overlong_absolute_dest() {
        #[cfg(windows)]
        let base = PathBuf::from(r"C:\Users").join("b".repeat(80));
        #[cfg(not(windows))]
        let base = PathBuf::from("/tmp").join("b".repeat(80));
        let rel = "c".repeat(950);
        #[cfg(any(windows, target_os = "macos"))]
        assert!(
            confine_path(&base, &rel).is_err(),
            "absolute dest + rel must fit OS PATH_MAX"
        );
        #[cfg(not(any(windows, target_os = "macos")))]
        {
            let _ = (base, rel);
        }
        #[cfg(windows)]
        assert!(confine_path(Path::new(r"C:\out"), "notes.txt").is_ok());
        #[cfg(not(windows))]
        assert!(confine_path(Path::new("/tmp/out"), "notes.txt").is_ok());
        assert!(confine_path(Path::new("."), &"d".repeat(950)).is_ok());
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
        let alt = unique_dest_path(&existing).expect("unique dest");
        assert_ne!(alt, existing);
        assert!(alt.to_string_lossy().contains("(1)"));
        assert!(!alt.exists());
    }

    // macOS rejects non-UTF-8 names (`Illegal byte sequence`).
    #[cfg(all(unix, not(target_os = "macos")))]
    #[test]
    fn unique_dest_path_preserves_non_utf8_stem() {
        use std::os::unix::ffi::OsStrExt;
        let dir = tempdir().unwrap();
        let dest = dir.path().join(std::ffi::OsStr::from_bytes(b"caf\xff.txt"));
        std::fs::write(&dest, b"x").unwrap();
        let alt = unique_dest_path(&dest).expect("unique dest");
        let name = alt.file_name().unwrap().as_bytes();
        assert!(name.starts_with(b"caf\xff"));
        assert!(name.ends_with(b".txt"));
        assert!(name.windows(4).any(|w| w == b" (1)"));
    }

    #[test]
    fn sweep_removes_stale_partials_not_real_files() {
        let dir = tempdir().unwrap();
        let dest = dir.path().join("out");
        std::fs::create_dir_all(dest.join("sub")).unwrap();
        std::fs::write(dest.join("keep.txt"), b"keep").unwrap();
        std::fs::write(dest.join("ok.txt.frostwallpart"), b"stale").unwrap();
        std::fs::write(dest.join("sub").join("x.txt.frostwallpart"), b"stale").unwrap();
        sweep_stale_partials(&dest);
        assert_eq!(std::fs::read(dest.join("keep.txt")).unwrap(), b"keep");
        assert!(!dest.join("ok.txt.frostwallpart").exists());
        assert!(!dest.join("sub").join("x.txt.frostwallpart").exists());
    }

    #[cfg(unix)]
    #[test]
    fn sweep_skips_symlink_named_partial() {
        use std::os::unix::fs::symlink;
        let dir = tempdir().unwrap();
        let secret = dir.path().join("secret.txt");
        std::fs::write(&secret, b"NO").unwrap();
        let dest = dir.path().join("out");
        std::fs::create_dir(&dest).unwrap();
        symlink(&secret, dest.join("x.txt.frostwallpart")).unwrap();
        sweep_stale_partials(&dest);
        assert_eq!(std::fs::read(&secret).unwrap(), b"NO");
        assert!(dest.join("x.txt.frostwallpart").symlink_metadata().is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn append_suffix_preserves_non_utf8() {
        use std::os::unix::ffi::OsStrExt;
        let p = PathBuf::from(std::ffi::OsStr::from_bytes(b"file\xff.txt"));
        let got = append_suffix(&p, PARTIAL_SUFFIX);
        assert_eq!(got.as_os_str().as_bytes(), b"file\xff.txt.frostwallpart");
    }

    #[test]
    fn create_nofollow_does_not_truncate_existing() {
        let dir = tempdir().unwrap();
        let mut p = dir.path().join("x.frostwallpart");
        std::fs::write(&p, b"keep").unwrap();
        let f = create_nofollow_file(&mut p).expect("exclusive create");
        drop(f);
        assert_eq!(std::fs::read(dir.path().join("x.frostwallpart")).unwrap(), b"keep");
        assert_ne!(p.file_name().and_then(|n| n.to_str()), Some("x.frostwallpart"));
        assert!(p
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.ends_with("frostwallpart")));
        assert_eq!(std::fs::read(&p).unwrap(), b"");
    }

    #[cfg(unix)]
    #[test]
    fn unique_dest_path_skips_dangling_symlink() {
        use std::os::unix::fs::symlink;
        let dir = tempdir().unwrap();
        let dest = dir.path().join("doc.txt");
        symlink(dir.path().join("missing.txt"), &dest).unwrap();
        let alt = unique_dest_path(&dest).expect("unique dest");
        assert_ne!(alt, dest);
        assert!(alt.to_string_lossy().contains("(1)"));
        assert!(std::fs::symlink_metadata(&dest).is_ok());
    }

    #[test]
    fn rename_noreplace_does_not_clobber() {
        let dir = tempdir().unwrap();
        let from = dir.path().join("new.txt");
        let to = dir.path().join("old.txt");
        std::fs::write(&from, b"new").unwrap();
        std::fs::write(&to, b"old").unwrap();
        assert!(rename_noreplace(&from, &to).is_err());
        assert_eq!(std::fs::read(&to).unwrap(), b"old");
        assert!(from.exists());
        let empty = dir.path().join("empty.txt");
        rename_noreplace(&from, &empty).expect("rename into free name");
        assert_eq!(std::fs::read(&empty).unwrap(), b"new");
        assert!(!from.exists());
    }

    #[test]
    fn confine_accepts_normal_relative() {
        let base = Path::new("/tmp/out");
        assert_eq!(confine_path(base, "a.txt").unwrap(), Path::new("/tmp/out/a.txt"));
        assert_eq!(
            confine_path(base, "dir/sub/b.txt").unwrap(),
            Path::new("/tmp/out/dir/sub/b.txt")
        );
        assert!(manifest_fits_dest(base, &[ManifestEntry { rel_path: "a.txt".into(), size: 1 }]).is_ok());
        let long = "a".repeat(4060);
        assert!(manifest_fits_dest(base, &[ManifestEntry { rel_path: long, size: 1 }]).is_err());
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

    #[test]
    fn validate_manifest_rejects_sized_directory_and_file_dir_clash() {
        let sized = vec![ManifestEntry {
            rel_path: "empty/".into(),
            size: 1,
        }];
        assert!(validate_manifest(&sized).unwrap_err().to_string().contains("size 0"));
        let clash = vec![
            ManifestEntry {
                rel_path: "a".into(),
                size: 1,
            },
            ManifestEntry {
                rel_path: "a/".into(),
                size: 0,
            },
        ];
        assert!(validate_manifest(&clash).is_err());
    }

    #[test]
    fn sealed_control_len_matches_seal_control() {
        let keys = SessionKeys::derive(b"frame-size");
        let msg = Message::Manifest(vec![
            ManifestEntry {
                rel_path: "a/b.txt".into(),
                size: 99,
            },
            ManifestEntry {
                rel_path: "c".into(),
                size: 1,
            },
        ]);
        let sealed = seal_control(&keys, &msg).unwrap();
        assert_eq!(sealed.len(), sealed_control_len(&msg).unwrap());
        assert!(sealed.len() <= transport::MAX_FRAME);
    }

    #[test]
    fn fifty_thousand_short_names_fit_one_frame() {
        let entries: Vec<ManifestEntry> = (0..MAX_FILES)
            .map(|i| ManifestEntry {
                rel_path: format!("f{i}"),
                size: 1,
            })
            .collect();
        ensure_control_fits(&Message::Manifest(entries))
            .expect("50k short names must fit the control frame");
    }

    #[test]
    fn long_path_manifest_rejected_before_wire() {
        let entries: Vec<ManifestEntry> = (0..MAX_FILES)
            .map(|i| ManifestEntry {
                rel_path: format!("d{i}/{}", "x".repeat(200)),
                size: 1,
            })
            .collect();
        let err = ensure_control_fits(&Message::Manifest(entries)).unwrap_err();
        assert!(err.to_string().contains("too large"), "{err}");
    }

    // ---- malicious sender helper ----
    struct EvilFile {
        rel: String,
        chunks: Vec<Vec<u8>>,
        hash: Option<[u8; 32]>,        // None => correct hash over plaintext
        declared_size: Option<u64>,    // None => sum of chunk lengths
    }

    async fn evil_send(conn: &mut Connection, keys: &SessionKeys, files: Vec<EvilFile>) {
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
        let (mut a, mut b) = loopback_pair().await;
        let keys = SessionKeys::derive(b"shared");
        let dir = tempdir().unwrap();
        let dest = dir.path().join("out");

        let evil = vec![EvilFile { rel: "../evil.txt".into(), chunks: vec![b"pwn".to_vec()], hash: None, declared_size: None }];
        let keys_a = keys.clone();
        tokio::spawn(async move { evil_send(&mut a, &keys_a, evil).await });

        let cancel = no_cancel();
        let r = recv(&mut b, &keys, &dest, &mut |_| {}, &cancel).await;
        assert!(r.is_err());
        assert!(!dir.path().join("evil.txt").exists());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn recv_refuses_symlink_escape_in_dest() {
        use std::os::unix::fs::symlink;
        let (mut a, mut b) = loopback_pair().await;
        let keys = SessionKeys::derive(b"symlink-escape");
        let dir = tempdir().unwrap();
        let dest = dir.path().join("out");
        fs::create_dir_all(&dest).await.unwrap();
        let secret = dir.path().join("secret");
        fs::create_dir_all(&secret).await.unwrap();
        symlink(&secret, dest.join("leak")).unwrap();

        let src = dir.path().join("leak");
        fs::create_dir_all(&src).await.unwrap();
        fs::write(src.join("x.txt"), b"TOPSECRET").await.unwrap();
        let items = collect_items(std::slice::from_ref(&src)).unwrap();

        let keys_r = keys.clone();
        let dest_r = dest.clone();
        let recv_cancel = no_cancel();
        let send_cancel = no_cancel();
        let mut on_send = |_p: Progress| {};
        let mut on_recv = |_p: Progress| {};
        let (send_res, recv_res) = tokio::join!(
            send(&mut a, &keys, &items, &mut on_send, &send_cancel),
            recv(&mut b, &keys_r, &dest_r, &mut on_recv, &recv_cancel),
        );
        assert!(recv_res.is_ok(), "recv remaps around dest symlink, got {recv_res:?}");
        assert!(send_res.is_ok(), "send={send_res:?}");
        assert!(
            !secret.join("x.txt").exists(),
            "payload must not land outside the download dir"
        );
        assert!(dest.join("leak").is_symlink());
        assert_eq!(
            fs::read(dest.join("leak (1)").join("x.txt")).await.unwrap(),
            b"TOPSECRET"
        );
    }

    #[cfg(unix)]
    #[test]
    fn path_has_symlink_component_sees_parent_link() {
        use std::os::unix::fs::symlink;
        let dir = tempdir().unwrap();
        let real = dir.path().join("real");
        std::fs::create_dir(&real).unwrap();
        let link = dir.path().join("link");
        symlink(&real, &link).unwrap();
        assert!(path_has_symlink_component(&link.join("out")));
        assert!(!path_has_symlink_component(&real.join("out")));
        assert!(!path_has_symlink_component(&real));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn recv_refuses_symlink_parent_of_dest() {
        use std::os::unix::fs::symlink;
        let (mut a, mut b) = loopback_pair().await;
        let keys = SessionKeys::derive(b"dest-parent-link");
        let dir = tempdir().unwrap();
        let real = dir.path().join("real");
        fs::create_dir_all(&real).await.unwrap();
        let link = dir.path().join("link");
        symlink(&real, &link).unwrap();
        let dest = link.join("out");

        let src = dir.path().join("doc.txt");
        fs::write(&src, b"TOPSECRET").await.unwrap();
        let items = vec![item(src, "doc.txt")];

        let keys_r = keys.clone();
        let dest_r = dest.clone();
        let recv_cancel = no_cancel();
        let send_cancel = no_cancel();
        let mut on_send = |_p: Progress| {};
        let mut on_recv = |_p: Progress| {};
        let (send_res, recv_res) = tokio::join!(
            send(&mut a, &keys, &items, &mut on_send, &send_cancel),
            recv(&mut b, &keys_r, &dest_r, &mut on_recv, &recv_cancel),
        );
        assert!(recv_res.is_err(), "recv must refuse dest parent symlink, got {recv_res:?}");
        assert!(
            send_res.is_err() || recv_res.is_err(),
            "send={send_res:?} recv={recv_res:?}"
        );
        assert!(
            !real.join("out").join("doc.txt").exists(),
            "payload must not land through the dest parent symlink"
        );
        assert!(!real.join("out").exists(), "must not mkdir through the dest parent symlink");
    }

    // ---- C3: peer exceeding declared size is aborted ----
    #[tokio::test]
    async fn recv_aborts_size_overrun() {
        let (mut a, mut b) = loopback_pair().await;
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
        tokio::spawn(async move { evil_send(&mut a, &keys_a, evil).await });

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
        let (mut a, mut b) = loopback_pair().await;
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
        tokio::spawn(async move { evil_send(&mut a, &keys_a, evil).await });

        let cancel = no_cancel();
        let r = recv(&mut b, &keys, &dest, &mut |_| {}, &cancel).await;
        assert!(r.is_err());
        assert!(!dest.join("bad.txt").exists());
        assert!(!dest.join("bad.txt.frostwallpart").exists());
    }

    #[tokio::test]
    async fn hash_mismatch_signals_reject_not_cancel() {
        let (mut a, mut b) = loopback_pair().await;
        let keys = SessionKeys::derive(b"hash-reject");
        let dir = tempdir().unwrap();
        let dest = dir.path().join("out");
        let evil = vec![EvilFile {
            rel: "bad.txt".into(),
            chunks: vec![b"contents".to_vec()],
            hash: Some([0xAAu8; 32]),
            declared_size: None,
        }];
        let recv_cancel = no_cancel();
        let mut on_recv = |_p: Progress| {};
        let (_, recv_res) = tokio::join!(
            evil_send(&mut a, &keys, evil),
            recv(&mut b, &keys, &dest, &mut on_recv, &recv_cancel),
        );
        assert!(
            recv_res.as_ref().err().is_some_and(is_integrity_fail),
            "{recv_res:?}"
        );
        let mut saw_reject = false;
        for _ in 0..4 {
            let reply = tokio::time::timeout(Duration::from_secs(2), a.recv())
                .await
                .expect("receiver must reply")
                .unwrap();
            match open_control(&keys, &reply).unwrap() {
                Message::Accept => continue,
                Message::Reject => {
                    saw_reject = true;
                    break;
                }
                other => panic!("expected Reject after Accept, got {other:?}"),
            }
        }
        assert!(saw_reject, "hash mismatch must send Reject, not Cancel");
    }

    #[tokio::test]
    async fn send_maps_post_accept_reject_to_integrity() {
        let (mut a, mut b) = loopback_pair().await;
        let keys = SessionKeys::derive(b"reject-integrity");
        let dir = tempdir().unwrap();
        let src = dir.path().join("x.bin");
        fs::write(&src, vec![0x11u8; CHUNK_SIZE + 8]).await.unwrap();
        let items = vec![item(src, "x.bin")];
        let keys_r = keys.clone();
        let recv_task = tokio::spawn(async move {
            let first = b.recv().await.unwrap();
            assert!(matches!(
                open_control(&keys_r, &first),
                Ok(Message::Manifest(_))
            ));
            b.send(&seal_control(&keys_r, &Message::Accept).unwrap())
                .await
                .unwrap();
            let _ = b.recv().await.unwrap();
            b.send(&seal_control(&keys_r, &Message::Reject).unwrap())
                .await
                .unwrap();
            b
        });
        let err = send(&mut a, &keys, &items, &mut |_| {}, &no_cancel())
            .await
            .unwrap_err();
        assert!(is_integrity_fail(&err), "{err}");
        assert!(!is_cancelled(&err));
        let _ = recv_task.await;
    }

    #[tokio::test]
    async fn hash_mismatch_then_second_transfer_on_same_pipe() {
        let (mut a, mut b) = loopback_pair().await;
        let keys = SessionKeys::derive(b"reuse-after-bad-hash");
        let dir = tempdir().unwrap();
        let dest = dir.path().join("out");
        let wrong_hash = [0xAAu8; 32];
        let evil = vec![EvilFile {
            rel: "bad.txt".into(),
            chunks: vec![b"contents".to_vec()],
            hash: Some(wrong_hash),
            declared_size: None,
        }];
        let recv_cancel = no_cancel();
        let mut on_recv = |_p: Progress| {};
        let (_, recv_res) = tokio::join!(
            evil_send(&mut a, &keys, evil),
            recv(&mut b, &keys, &dest, &mut on_recv, &recv_cancel),
        );
        assert!(recv_res.is_err());
        drain_after_abort(&mut a).await;
        drain_after_abort(&mut b).await;

        let src2 = dir.path().join("ok.txt");
        fs::write(&src2, b"second").await.unwrap();
        let items2 = vec![item(src2, "ok.txt")];
        let dest2 = dir.path().join("out2");
        let keys_r = keys.clone();
        let recv_cancel = no_cancel();
        let mut on_recv2 = |_p: Progress| {};
        let recv_task = tokio::spawn(async move {
            recv(&mut b, &keys_r, &dest2, &mut on_recv2, &recv_cancel).await
        });
        let send_cancel2 = no_cancel();
        let mut on_send2 = |_p: Progress| {};
        send(&mut a, &keys, &items2, &mut on_send2, &send_cancel2)
            .await
            .unwrap();
        recv_task.await.unwrap().unwrap();
        assert_eq!(
            fs::read(dir.path().join("out2").join("ok.txt"))
                .await
                .unwrap(),
            b"second"
        );
    }

    // ---- C3b: peer sending fewer bytes than declared is rejected ----
    #[tokio::test]
    async fn recv_rejects_undersized_file() {
        let (mut a, mut b) = loopback_pair().await;
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
        tokio::spawn(async move { evil_send(&mut a, &keys_a, evil).await });

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

        let items = vec![item(src, "hello.txt")];
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
    async fn send_recv_does_not_clobber_existing_file() {
        let (mut a, mut b) = loopback_pair().await;
        let keys = SessionKeys::derive(b"no-clobber");
        let dir = tempdir().unwrap();
        let src = dir.path().join("hello.txt");
        fs::write(&src, b"incoming").await.unwrap();
        let dest = dir.path().join("out");
        fs::create_dir_all(&dest).await.unwrap();
        fs::write(dest.join("hello.txt"), b"keep").await.unwrap();
        let items = vec![item(src, "hello.txt")];
        let keys_r = keys.clone();
        let dest_r = dest.clone();
        let cancel = no_cancel();
        let recv_task =
            tokio::spawn(async move { recv(&mut b, &keys_r, &dest_r, &mut |_| {}, &cancel).await });
        send(&mut a, &keys, &items, &mut |_| {}, &no_cancel()).await.unwrap();
        recv_task.await.unwrap().unwrap();
        assert_eq!(fs::read(dest.join("hello.txt")).await.unwrap(), b"keep");
        assert_eq!(fs::read(dest.join("hello (1).txt")).await.unwrap(), b"incoming");
    }

    #[tokio::test]
    async fn send_recv_uniques_folder_when_dest_has_file() {
        let (mut a, mut b) = loopback_pair().await;
        let keys = SessionKeys::derive(b"file-dir-clash");
        let dir = tempdir().unwrap();
        let src = dir.path().join("photos");
        fs::create_dir_all(&src).await.unwrap();
        fs::write(src.join("a.txt"), b"A").await.unwrap();
        fs::write(src.join("b.txt"), b"B").await.unwrap();
        let dest = dir.path().join("out");
        fs::create_dir_all(&dest).await.unwrap();
        fs::write(dest.join("photos"), b"keep").await.unwrap();
        let items = collect_items(std::slice::from_ref(&src)).unwrap();
        let keys_r = keys.clone();
        let dest_r = dest.clone();
        let cancel = no_cancel();
        let recv_task =
            tokio::spawn(async move { recv(&mut b, &keys_r, &dest_r, &mut |_| {}, &cancel).await });
        send(&mut a, &keys, &items, &mut |_| {}, &no_cancel()).await.unwrap();
        recv_task.await.unwrap().unwrap();
        assert_eq!(fs::read(dest.join("photos")).await.unwrap(), b"keep");
        assert_eq!(fs::read(dest.join("photos (1)").join("a.txt")).await.unwrap(), b"A");
        assert_eq!(fs::read(dest.join("photos (1)").join("b.txt")).await.unwrap(), b"B");
    }

    #[cfg(unix)]
    #[test]
    fn remap_dest_skips_symlink_prefix() {
        use std::os::unix::fs::symlink;
        let dir = tempdir().unwrap();
        let dest = dir.path().join("out");
        std::fs::create_dir(&dest).unwrap();
        let secret = dir.path().join("secret");
        std::fs::create_dir(&secret).unwrap();
        symlink(&secret, dest.join("photos")).unwrap();
        let confined = confine_path(&dest, "photos/a.txt").unwrap();
        let mut remap = HashMap::new();
        let got = remap_dest(&dest, &confined, &mut remap).unwrap();
        assert_eq!(got, dest.join("photos (1)").join("a.txt"));
        assert!(secret.read_dir().unwrap().next().is_none());
    }

    #[cfg(windows)]
    fn make_junction(link: &Path, target: &Path) {
        let status = std::process::Command::new("cmd")
            .args([
                "/C",
                "mklink",
                "/J",
                &link.to_string_lossy(),
                &target.to_string_lossy(),
            ])
            .status()
            .expect("mklink");
        assert!(status.success(), "mklink /J {link:?} -> {target:?}");
    }

    #[cfg(windows)]
    #[test]
    fn remap_dest_skips_junction_prefix() {
        let dir = tempdir().unwrap();
        let dest = dir.path().join("out");
        std::fs::create_dir(&dest).unwrap();
        let secret = dir.path().join("secret");
        std::fs::create_dir(&secret).unwrap();
        make_junction(&dest.join("photos"), &secret);
        assert!(is_link_like_path(&dest.join("photos")));
        let confined = confine_path(&dest, "photos/a.txt").unwrap();
        let mut remap = HashMap::new();
        let got = remap_dest(&dest, &confined, &mut remap).unwrap();
        assert_eq!(got, dest.join("photos (1)").join("a.txt"));
        assert!(secret.read_dir().unwrap().next().is_none());
    }

    #[cfg(windows)]
    #[test]
    fn collect_items_skips_junctions() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("share");
        std::fs::create_dir_all(root.join("sub")).unwrap();
        std::fs::write(root.join("real.txt"), b"x").unwrap();
        let secret = dir.path().join("secret");
        std::fs::create_dir(&secret).unwrap();
        std::fs::write(secret.join("hidden.txt"), b"NO").unwrap();
        make_junction(&root.join("leak"), &secret);
        let items = collect_items(std::slice::from_ref(&root)).unwrap();
        let rels: Vec<String> = items.iter().map(|i| i.rel_path.clone()).collect();
        assert!(rels.iter().any(|r| r == "share/real.txt"));
        assert!(!rels.iter().any(|r| r.contains("leak")));
    }

    #[cfg(unix)]
    #[test]
    fn is_link_like_path_sees_symlink() {
        use std::os::unix::fs::symlink;
        let dir = tempdir().unwrap();
        let dest = dir.path().join("out");
        std::fs::create_dir(&dest).unwrap();
        symlink(&dest, dir.path().join("link")).unwrap();
        assert!(is_link_like_path(&dir.path().join("link")));
        assert!(!is_link_like_path(&dest));
        assert!(is_real_dir(&dest));
        assert!(!is_real_dir(&dir.path().join("link")));
    }

    #[tokio::test]
    async fn simultaneous_send_reports_collision() {
        let (mut a, mut b) = loopback_pair().await;
        let keys = SessionKeys::derive(b"collide");
        let dir = tempdir().unwrap();
        let src_a = dir.path().join("a.txt");
        let src_b = dir.path().join("b.txt");
        fs::write(&src_a, b"a").await.unwrap();
        fs::write(&src_b, b"b").await.unwrap();
        let items_a = vec![item(src_a, "a.txt")];
        let items_b = vec![item(src_b, "b.txt")];
        let cancel_a = no_cancel();
        let cancel_b = no_cancel();
        let mut on_a = |_p: Progress| {};
        let mut on_b = |_p: Progress| {};
        let (ra, rb) = tokio::join!(
            send(&mut a, &keys, &items_a, &mut on_a, &cancel_a),
            send(&mut b, &keys, &items_b, &mut on_b, &cancel_b),
        );
        let ea = ra.unwrap_err().to_string();
        let eb = rb.unwrap_err().to_string();
        assert!(
            ea.contains("same time") && eb.contains("same time"),
            "{ea} / {eb}"
        );
    }

    #[tokio::test]
    async fn reject_during_accept_unblocks_sender() {
        let (mut a, mut b) = loopback_pair().await;
        let keys = SessionKeys::derive(b"collide-reject");
        let dir = tempdir().unwrap();
        let src = dir.path().join("a.txt");
        fs::write(&src, b"a").await.unwrap();
        let items = vec![item(src, "a.txt")];
        let keys_b = keys.clone();
        let peer = tokio::spawn(async move {
            let first = b.recv().await.unwrap();
            assert!(matches!(open_control(&keys_b, &first), Ok(Message::Manifest(_))));
            send_or_stall(&mut b, &seal_control(&keys_b, &Message::Reject).unwrap())
                .await
                .unwrap();
        });
        let err = tokio::time::timeout(
            Duration::from_secs(5),
            send(&mut a, &keys, &items, &mut |_| {}, &no_cancel()),
        )
        .await
        .expect("Reject must unblock accept wait")
        .unwrap_err();
        assert!(
            err.to_string().contains("transfer rejected by peer"),
            "{err}"
        );
        peer.await.unwrap();
    }

    #[tokio::test]
    async fn exchange_hello_both_sides() {
        let (mut a, mut b) = loopback_pair().await;
        let keys = SessionKeys::derive(b"hello-secret");
        let (na, nb) = tokio::join!(
            exchange_hello(&mut a, &keys, Some("Host Mac")),
            exchange_hello(&mut b, &keys, Some("Join PC")),
        );
        assert_eq!(na.as_ref().unwrap().as_deref(), Some("Join PC"));
        assert_eq!(nb.as_ref().unwrap().as_deref(), Some("Host Mac"));
    }

    #[tokio::test]
    async fn exchange_hello_peer_drop_is_error() {
        let (mut a, b) = loopback_pair().await;
        drop(b);
        let keys = SessionKeys::derive(b"hello-drop");
        let err = exchange_hello(&mut a, &keys, Some("Host")).await;
        assert!(err.is_err(), "dead pipe must not look like a paired session: {err:?}");
    }

    #[tokio::test]
    async fn accept_wait_times_out_without_reply() {
        let (mut a, _b) = loopback_pair().await;
        let keys = SessionKeys::derive(b"timeout-secret");
        let err = recv_or_cancel_within(
            &mut a,
            &no_cancel(),
            &keys,
            Duration::from_millis(80),
            "timed out waiting for the peer to accept",
        )
        .await
        .unwrap_err();
        assert!(
            err.to_string().contains("timed out waiting for the peer to accept"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn send_recv_folder_preserves_structure() {
        let (mut a, mut b) = loopback_pair().await;
        let keys = SessionKeys::derive(b"folder-secret");
        let dir = tempdir().unwrap();
        let src_root = dir.path().join("data");
        fs::create_dir_all(src_root.join("sub")).await.unwrap();
        fs::create_dir_all(src_root.join("empty")).await.unwrap();
        fs::write(src_root.join("a.txt"), b"aaa").await.unwrap();
        fs::write(src_root.join("sub").join("b.txt"), b"bbbbbbbb").await.unwrap();

        let items = collect_items(std::slice::from_ref(&src_root)).unwrap();
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
        assert!(dest.join("data/empty").is_dir());
    }

    #[tokio::test]
    async fn progress_reports_bytes() {
        let (mut a, mut b) = loopback_pair().await;
        let keys = SessionKeys::derive(b"prog-secret");
        let dir = tempdir().unwrap();
        let src = dir.path().join("big.bin");
        let content = vec![0x11u8; CHUNK_SIZE * 2 + 1234];
        fs::write(&src, &content).await.unwrap();

        let items = vec![item(src, "big.bin")];
        let dest = dir.path().join("out");

        let keys_r = keys.clone();
        let dest_r = dest.clone();
        let cancel = no_cancel();
        let recv_task =
            tokio::spawn(async move { recv(&mut b, &keys_r, &dest_r, &mut |_| {}, &cancel).await });

        static LAST_PCT: AtomicU64 = AtomicU64::new(0);
        send(&mut a, &keys, &items, &mut |p: Progress| {
            let pct = p.transferred * 100 / p.total.max(1);
            LAST_PCT.store(pct, Ordering::SeqCst);
        }, &no_cancel())
        .await
        .unwrap();
        recv_task.await.unwrap().unwrap();

        assert_eq!(LAST_PCT.load(Ordering::SeqCst), 100);
    }

    #[tokio::test]
    async fn sender_stops_when_peer_cancels_mid_payload() {
        let (mut a, mut b) = loopback_pair().await;
        let keys = SessionKeys::derive(b"mid-cancel");
        let dir = tempdir().unwrap();
        let src = dir.path().join("big.bin");
        let n = CHUNK_SIZE * 8;
        fs::write(&src, vec![0xABu8; n]).await.unwrap();
        let items = vec![item(src, "big.bin")];
        let keys_r = keys.clone();
        let recv_task = tokio::spawn(async move {
            let first = b.recv().await.unwrap();
            assert!(matches!(
                open_control(&keys_r, &first),
                Ok(Message::Manifest(_))
            ));
            b.send(&seal_control(&keys_r, &Message::Accept).unwrap())
                .await
                .unwrap();
            let _ = b.recv().await.unwrap();
            b.send(&seal_control(&keys_r, &Message::Cancel).unwrap())
                .await
                .unwrap();
            b
        });
        let last = std::sync::Arc::new(AtomicU64::new(0));
        let last_cb = last.clone();
        let send_res = send(
            &mut a,
            &keys,
            &items,
            &mut |p: Progress| {
                last_cb.store(p.transferred, Ordering::SeqCst);
            },
            &no_cancel(),
        )
        .await;
        assert!(
            send_res.as_ref().err().is_some_and(is_cancelled),
            "{send_res:?}"
        );
        let got = last.load(Ordering::SeqCst);
        assert!(
            got > 0 && got < n as u64,
            "must stop mid-payload, transferred={got} total={n}"
        );
        let _ = recv_task.await;
    }

    #[tokio::test]
    async fn recv_local_cancel_stops_sender() {
        let (mut a, mut b) = loopback_pair().await;
        let keys = SessionKeys::derive(b"recv-local-cancel");
        let dir = tempdir().unwrap();
        let src = dir.path().join("big.bin");
        let n = CHUNK_SIZE * 8;
        fs::write(&src, vec![0xCDu8; n]).await.unwrap();
        let items = vec![item(src, "big.bin")];
        let dest = dir.path().join("out");
        let recv_flag = std::sync::Arc::new(AtomicBool::new(false));
        let recv_flag_cb = recv_flag.clone();
        let mut on_recv = |p: Progress| {
            if p.transferred > 0 {
                recv_flag_cb.store(true, Ordering::SeqCst);
            }
        };
        let send_cancel = no_cancel();
        let mut on_send = |_p: Progress| {};
        let (send_res, recv_res) = tokio::time::timeout(
            Duration::from_secs(5),
            async {
                tokio::join!(
                    send(&mut a, &keys, &items, &mut on_send, &send_cancel),
                    recv(&mut b, &keys, &dest, &mut on_recv, &recv_flag),
                )
            },
        )
        .await
        .expect("recv cancel must notify sender (not wait for Done timeout)");
        assert!(
            recv_res.as_ref().err().is_some_and(is_local_cancel),
            "{recv_res:?}"
        );
        assert!(
            send_res.as_ref().err().is_some_and(is_cancelled),
            "sender must see Cancel, got {send_res:?}"
        );
    }

    #[tokio::test]
    async fn cancel_then_second_transfer_on_same_pipe() {
        let (mut a, mut b) = loopback_pair().await;
        let keys = SessionKeys::derive(b"cancel-reuse");
        let dir = tempdir().unwrap();
        let src1 = dir.path().join("big.bin");
        fs::write(&src1, vec![0xABu8; 400_000]).await.unwrap();
        let src2 = dir.path().join("ok.txt");
        fs::write(&src2, b"second").await.unwrap();
        let items1 = vec![item(src1, "big.bin")];
        let dest = dir.path().join("out");
        let recv_flag = std::sync::Arc::new(AtomicBool::new(false));
        let recv_flag_cb = recv_flag.clone();
        let send_flag = std::sync::Arc::new(AtomicBool::new(false));
        let send_flag_cb = send_flag.clone();
        let mut on_send = |p: Progress| {
            if p.transferred > 0 {
                send_flag_cb.store(true, Ordering::SeqCst);
            }
        };
        let mut on_recv = |p: Progress| {
            if p.transferred > 0 {
                recv_flag_cb.store(true, Ordering::SeqCst);
            }
        };
        let (send_res, recv_res) = tokio::join!(
            send(&mut a, &keys, &items1, &mut on_send, &send_flag),
            recv(&mut b, &keys, &dest, &mut on_recv, &recv_flag),
        );
        assert!(
            send_res.as_ref().err().is_some_and(is_cancelled)
                || recv_res.as_ref().err().is_some_and(is_cancelled),
            "send={send_res:?} recv={recv_res:?}"
        );
        drain_after_abort(&mut a).await;
        drain_after_abort(&mut b).await;

        let items2 = vec![item(src2, "ok.txt")];
        let dest2 = dir.path().join("out2");
        let keys_r = keys.clone();
        let recv_cancel = no_cancel();
        let mut on_recv2 = |_p: Progress| {};
        let recv_task = tokio::spawn(async move {
            recv(&mut b, &keys_r, &dest2, &mut on_recv2, &recv_cancel).await
        });
        let send_cancel2 = no_cancel();
        let mut on_send2 = |_p: Progress| {};
        send(&mut a, &keys, &items2, &mut on_send2, &send_cancel2)
            .await
            .unwrap();
        recv_task.await.unwrap().unwrap();
        assert_eq!(
            fs::read(dir.path().join("out2").join("ok.txt"))
                .await
                .unwrap(),
            b"second"
        );
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

        let items = collect_items(std::slice::from_ref(&root)).unwrap();
        let rels: Vec<String> = items.iter().map(|i| i.rel_path.clone()).collect();
        assert!(rels.iter().any(|r| r == "share/real.txt"));
        assert!(!rels.iter().any(|r| r.contains("leak")));
    }

    #[cfg(unix)]
    #[test]
    fn rel_utf8_rejects_non_utf8_name() {
        use std::os::unix::ffi::OsStrExt;
        let p = PathBuf::from(std::ffi::OsStr::from_bytes(b"/tmp/bad\xff.txt"));
        let err = rel_utf8(&p, None).unwrap_err();
        assert!(
            err.to_string().contains("invalid file name"),
            "got {err}"
        );
        let err = rel_utf8(&p, Some(Path::new("/tmp"))).unwrap_err();
        assert!(
            err.to_string().contains("invalid file name"),
            "got {err}"
        );
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
        assert_eq!(
            items.iter().find(|i| i.rel_path == "single.txt").unwrap().size,
            1
        );
    }

    #[test]
    fn collect_walks_sibling_directories() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("share");
        std::fs::create_dir_all(root.join("a")).unwrap();
        std::fs::create_dir_all(root.join("b")).unwrap();
        std::fs::write(root.join("a").join("1.txt"), b"a").unwrap();
        std::fs::write(root.join("b").join("2.txt"), b"bb").unwrap();
        let items = collect_items(std::slice::from_ref(&root)).unwrap();
        let rels: Vec<&str> = items.iter().map(|i| i.rel_path.as_str()).collect();
        assert!(rels.contains(&"share/a/1.txt"));
        assert!(rels.contains(&"share/b/2.txt"));
    }

    #[test]
    fn collect_empty_dir_emits_dir_entry() {
        let dir = tempdir().unwrap();
        let empty = dir.path().join("empty");
        std::fs::create_dir_all(&empty).unwrap();
        let items = collect_items(std::slice::from_ref(&empty)).unwrap();
        assert_eq!(items.len(), 1);
        assert!(items[0].is_dir);
        assert_eq!(items[0].rel_path, "empty/");
        assert_eq!(items[0].size, 0);
    }

    #[tokio::test]
    async fn send_recv_empty_folder() {
        let (mut a, mut b) = loopback_pair().await;
        let keys = SessionKeys::derive(b"empty-dir");
        let dir = tempdir().unwrap();
        let src = dir.path().join("blank");
        fs::create_dir_all(&src).await.unwrap();
        let items = collect_items(std::slice::from_ref(&src)).unwrap();
        let dest = dir.path().join("out");
        let keys_r = keys.clone();
        let dest_r = dest.clone();
        let cancel = no_cancel();
        let recv_task =
            tokio::spawn(async move { recv(&mut b, &keys_r, &dest_r, &mut |_| {}, &cancel).await });
        let mut ticks = 0u32;
        send(&mut a, &keys, &items, &mut |_| { ticks += 1; }, &no_cancel())
            .await
            .unwrap();
        recv_task.await.unwrap().unwrap();
        assert!(ticks >= 1, "Accept must emit a progress tick so the UI leaves waiting-for-accept");
        assert!(dest.join("blank").is_dir());
        assert!(dest.join("blank").read_dir().unwrap().next().is_none());
    }

    #[tokio::test]
    async fn send_empty_list_errors_before_wire() {
        let (mut a, _b) = loopback_pair().await;
        let keys = SessionKeys::derive(b"empty");
        let err = send(&mut a, &keys, &[], &mut |_| {}, &no_cancel())
            .await
            .unwrap_err();
        assert!(err.to_string().contains("nothing to send"), "{err}");
    }

    #[tokio::test]
    async fn send_missing_file_after_accept_cancels_peer() {
        let (mut a, mut b) = loopback_pair().await;
        let keys = SessionKeys::derive(b"missing");
        let dir = tempdir().unwrap();
        let dest = dir.path().join("out");
        let items = vec![SendItem {
            source: dir.path().join("gone.txt"),
            rel_path: "gone.txt".into(),
            size: 4,
            is_dir: false,
        }];
        let keys_r = keys.clone();
        let dest_r = dest.clone();
        let send_cancel = no_cancel();
        let recv_cancel = no_cancel();
        let mut on_send = |_p: Progress| {};
        let mut on_recv = |_p: Progress| {};
        let (send_res, recv_res) = tokio::time::timeout(
            Duration::from_secs(5),
            async {
                tokio::join!(
                    send(&mut a, &keys, &items, &mut on_send, &send_cancel),
                    recv(&mut b, &keys_r, &dest_r, &mut on_recv, &recv_cancel),
                )
            },
        )
        .await
        .expect("missing-file send must not hang the receiver");
        assert!(send_res.is_err(), "{send_res:?}");
        assert!(recv_res.is_err(), "{recv_res:?}");
        assert!(
            is_cancelled(recv_res.as_ref().unwrap_err()),
            "receiver should see Cancel, got {recv_res:?}"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn send_does_not_follow_symlink_swapped_after_collect() {
        use std::os::unix::fs::symlink;
        let (mut a, mut b) = loopback_pair().await;
        let keys = SessionKeys::derive(b"swap");
        let dir = tempdir().unwrap();
        let src = dir.path().join("doc.txt");
        std::fs::write(&src, b"ok").unwrap();
        let secret = dir.path().join("secret.txt");
        std::fs::write(&secret, b"TOPSECRET").unwrap();
        let items = vec![item(src.clone(), "doc.txt")];
        std::fs::remove_file(&src).unwrap();
        symlink(&secret, &src).unwrap();
        let dest = dir.path().join("out");
        let keys_r = keys.clone();
        let dest_r = dest.clone();
        let send_cancel = no_cancel();
        let recv_cancel = no_cancel();
        let mut on_send = |_p: Progress| {};
        let mut on_recv = |_p: Progress| {};
        let (send_res, recv_res) = tokio::time::timeout(
            Duration::from_secs(5),
            async {
                tokio::join!(
                    send(&mut a, &keys, &items, &mut on_send, &send_cancel),
                    recv(&mut b, &keys_r, &dest_r, &mut on_recv, &recv_cancel),
                )
            },
        )
        .await
        .expect("symlink-swap send must not hang");
        assert!(
            send_res
                .as_ref()
                .err()
                .is_some_and(|e| e.to_string().contains("symlink")),
            "{send_res:?}"
        );
        assert!(recv_res.is_err(), "{recv_res:?}");
        let leaked = dest.join("doc.txt");
        if leaked.exists() {
            let body = std::fs::read(&leaked).unwrap();
            assert_ne!(body, b"TOPSECRET");
        }
    }

    #[test]
    fn collect_items_stops_when_cancelled() {
        let flag = AtomicBool::new(true);
        let err = collect_items_cancellable(&[PathBuf::from(".")], &flag).unwrap_err();
        assert!(is_cancelled(&err), "{err}");
    }

    #[test]
    fn open_control_error_omits_payload_bytes() {
        let keys = SessionKeys::derive(b"ctrl-secret");
        let marker = vec![0xAAu8; 64];
        let frame = protocol::encode(&Message::Chunk(marker)).unwrap();
        let err = open_control(&keys, &frame).unwrap_err().to_string();
        assert!(err.contains("expected encrypted control message"), "{err}");
        assert!(!err.contains("aa"), "{err}");
        assert!(!err.contains("AA"), "{err}");
        assert!(!err.contains("[170"), "{err}");
    }
}
