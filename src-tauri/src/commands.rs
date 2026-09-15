//! Tauri command layer: exposes host/join/send/liveness to the frontend and
//! runs a per-session coordinator task that owns the connection, racing local
//! send commands against incoming transfers (serialized, never concurrent).

use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Result;
use serde::Serialize;
use tauri::{async_runtime, AppHandle, Emitter, Manager, State};
use tokio::sync::{mpsc, oneshot, Mutex};
use tauri::async_runtime::JoinHandle;

use crate::crypto::SessionKeys;
use crate::discovery::{self, Discovery};
use crate::internet;
use crate::liveness;
use crate::protocol::Message;
use crate::session::{self, Session};
use crate::transfer;
use crate::transport::{self, Connection};

async fn optional_mailbox_url(state: &AppState) -> Option<String> {
    let stored = state
        .mailbox_url
        .lock()
        .map(|g| g.clone())
        .ok()
        .flatten();
    crate::config::configured_mailbox_url(&stored)
}

const EV_PROGRESS: &str = "frostwall://progress";
const EV_TRANSFER_START: &str = "frostwall://transfer-start";
const EV_TRANSFER_PENDING: &str = "frostwall://transfer-pending";
const EV_TRANSFER_DONE: &str = "frostwall://transfer-done";
const EV_PAIRED: &str = "frostwall://paired";
const EV_DISCONNECT: &str = "frostwall://disconnected";
const EV_ERROR: &str = "frostwall://error";
const EV_NOTICE: &str = "frostwall://notice";
const EV_INVITE: &str = "frostwall://invite";
const EV_PAIRING: &str = "frostwall://pairing";
const EV_RECEIVED: &str = "frostwall://received";

/// Max failed pairing handshakes before the host aborts (online brute-force
/// bound on the 6-digit code).
const MAX_PAIRING_ATTEMPTS: u32 = 5;
/// Max stalled handshakes (slowloris bound) before the host gives up.
const MAX_STALL_ATTEMPTS: u32 = 20;
/// How long the receiver may sit on the incoming-file prompt. Same window as
/// sender `ACCEPT_REPLY_TIMEOUT`: SAS confirm plus file-list review.
const DECISION_TIMEOUT: Duration = Duration::from_secs(6 * 60);
/// Extra wait, after the initial 8s home attempt, to refresh a relay-less invite.
const RELAY_REFRESH_WAIT: Duration = Duration::from_secs(25);
/// Re-extend optional mailbox TTL while the Remote host is still waiting.
const MAILBOX_REFRESH_WAIT: Duration = Duration::from_secs(8 * 60);

struct AbortOnDrop(async_runtime::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[derive(Clone, Serialize)]
struct TransferItem {
    name: String,
    size: u64,
}

/// Names shown in the UI. Full `file_count` / `total` stay accurate; a 50k-file
/// manifest must not freeze the webview or blow the IPC payload.
const UI_ITEM_PREVIEW: usize = 32;

fn transfer_preview(items: &[TransferItem]) -> Vec<TransferItem> {
    items.iter().take(UI_ITEM_PREVIEW).cloned().collect()
}

/// UI `has_relay`: public IP is a WAN path. Still hunt n0 if relays are empty.
fn remote_dialable(relays: &[String], ips: &[String]) -> bool {
    !relays.is_empty() || !ips.is_empty()
}

#[derive(Clone, Serialize)]
struct TransferStartPayload {
    direction: &'static str, // "sending" | "receiving"
    items: Vec<TransferItem>,
    total: u64,
    file_count: usize,
    epoch: u64,
}

#[derive(Clone, Serialize)]
struct ProgressPayload {
    transferred: u64,
    total: u64,
    percent: f64,
    direction: &'static str,
    epoch: u64,
}

#[derive(Clone, Serialize)]
struct TransferDonePayload {
    ok: bool,
    epoch: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Clone, Serialize)]
struct NoticePayload {
    message: String,
    epoch: u64,
}

#[derive(Clone, Serialize)]
struct ReceivedPayload {
    dest: String,
    epoch: u64,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InvitePayload {
    invite: String,
    code: String,
    has_relay: bool,
    mailbox_ok: bool,
    epoch: u64,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct PairedPayload {
    peer_name: Option<String>,
    local_name: Option<String>,
    epoch: u64,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct PairingPayload {
    on: bool,
    epoch: u64,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ErrorPayload {
    message: String,
    epoch: u64,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct DisconnectPayload {
    epoch: u64,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DiscoveredPeer {
    pub display_name: String,
    pub address: String,
    pub port: u16,
}

/// Snapshot of user-tunable config returned to the frontend (camelCase JSON).
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfigPayload {
    pub download_dir: Option<String>,
    pub device_name: Option<String>,
    pub mailbox_url: Option<String>,
    pub remote_available: bool,
}

enum SessionCmd {
    Send {
        paths: Vec<PathBuf>,
        reply: oneshot::Sender<Result<()>>,
    },
}

/// Shared state managed by Tauri.
pub struct AppState {
    cmd_tx: Mutex<Option<mpsc::Sender<SessionCmd>>>,
    liveness_key: Mutex<Option<[u8; 32]>>,
    download_dir: sync::Mutex<Option<String>>,
    device_name: sync::Mutex<Option<String>>,
    /// Base URL of the mailbox rendezvous service, used for internet
    /// (non-LAN) sessions. None until the user configures one.
    mailbox_url: sync::Mutex<Option<String>>,
    /// True while a transfer (send or receive) is in flight. Guards against a
    /// second transfer being queued on top of the current one.
    in_flight: sync::Mutex<bool>,
    /// Serializes config load→modify→save so concurrent set_download_dir /
    /// set_device_name cannot clobber each other's field.
    config_lock: sync::Mutex<()>,
    /// Handle to the in-flight host/join task so it can be cancelled (N2:
    /// previously the spawned task + listener + mDNS daemon leaked if the
    /// user disconnected before pairing completed).
    pairing_task: Mutex<Option<JoinHandle<()>>>,
    /// Live-session coordinator. `cmd_tx = None` only unblocks the idle
    /// `select`; a hung `conn.send` keeps the pipe up until this is aborted.
    coordinator_task: Mutex<Option<JoinHandle<()>>>,
    /// Set while the UI decides whether to accept an incoming transfer.
    incoming_decision: Mutex<Option<oneshot::Sender<bool>>>,
    /// Cancel flag for the transfer currently owned by the coordinator.
    active_cancel: sync::Mutex<Option<Arc<AtomicBool>>>,
    /// Display name of the peer we're connecting to (join side).
    peer_display_name: Mutex<Option<String>>,
    /// Active internet-host mailbox registration to unregister on disconnect/clear.
    internet_cleanup: Mutex<Option<InternetCleanup>>,
    /// Bumped on every `clear()` / disconnect so a host/join that was
    /// mid-bind (no `pairing_task` yet) cannot come back as a zombie session.
    /// `Arc` so LAN browse can observe a cancel from `spawn_blocking`.
    session_epoch: Arc<AtomicU64>,
}

/// Mailbox registration held by an internet-mode host until pairing completes
/// or the session is torn down.
struct InternetCleanup {
    mailbox: Option<internet::Mailbox>,
    code: String,
    token: Option<String>,
}

impl Default for AppState {
    fn default() -> Self {
        Self::new()
    }
}

impl AppState {
    pub fn new() -> Self {
        let cfg = crate::config::load();
        AppState {
            cmd_tx: Mutex::new(None),
            liveness_key: Mutex::new(None),
            download_dir: sync::Mutex::new(cfg.download_dir),
            device_name: sync::Mutex::new(cfg.device_name),
            mailbox_url: sync::Mutex::new(cfg.mailbox_url),
            in_flight: sync::Mutex::new(false),
            config_lock: sync::Mutex::new(()),
            pairing_task: Mutex::new(None),
            coordinator_task: Mutex::new(None),
            incoming_decision: Mutex::new(None),
            active_cancel: sync::Mutex::new(None),
            peer_display_name: Mutex::new(None),
            internet_cleanup: Mutex::new(None),
            session_epoch: Arc::new(AtomicU64::new(0)),
        }
    }

    fn epoch(&self) -> u64 {
        self.session_epoch.load(Ordering::SeqCst)
    }

    async fn cleanup_internet(&self) {
        if let Some(c) = self.internet_cleanup.lock().await.take() {
            if let Some(mailbox) = c.mailbox {
                mailbox.unregister(&c.code, c.token.as_deref()).await;
            }
        }
    }

    async fn abort_pairing(&self) {
        if let Some(h) = self.pairing_task.lock().await.take() {
            h.abort();
        }
    }

    async fn abort_coordinator(&self) {
        if let Some(h) = self.coordinator_task.lock().await.take() {
            h.abort();
        }
    }

    fn trigger_cancel(&self) {
        if let Ok(g) = self.active_cancel.lock() {
            if let Some(flag) = g.as_ref() {
                flag.store(true, Ordering::SeqCst);
            }
        }
    }

    async fn clear(&self) {
        self.session_epoch.fetch_add(1, Ordering::SeqCst);
        self.trigger_cancel();
        self.abort_pairing().await;
        self.abort_coordinator().await;
        if let Some(tx) = self.incoming_decision.lock().await.take() {
            let _ = tx.send(false);
        }
        *self.cmd_tx.lock().await = None;
        *self.liveness_key.lock().await = None;
        if let Ok(mut g) = self.in_flight.lock() {
            *g = false;
        }
        if let Ok(mut g) = self.active_cancel.lock() {
            *g = None;
        }
        self.cleanup_internet().await;
        *self.peer_display_name.lock().await = None;
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn set_in_flight(app: &AppHandle, v: bool) {
    if let Some(st) = app.try_state::<AppState>() {
        if let Ok(mut g) = st.in_flight.lock() {
            *g = v;
        }
    }
}

fn set_in_flight_if_live(app: &AppHandle, epoch: u64, v: bool) {
    if still_epoch(app, epoch) {
        set_in_flight(app, v);
    }
}

fn install_cancel(state: &AppState) -> Arc<AtomicBool> {
    if let Ok(mut g) = state.active_cancel.lock() {
        if let Some(existing) = g.as_ref() {
            return existing.clone();
        }
        let flag = Arc::new(AtomicBool::new(false));
        *g = Some(flag.clone());
        return flag;
    }
    Arc::new(AtomicBool::new(true))
}

fn install_cancel_if_live(app: &AppHandle, epoch: u64) -> Arc<AtomicBool> {
    if let Some(st) = app.try_state::<AppState>() {
        if st.epoch() == epoch {
            return install_cancel(&st);
        }
    }
    Arc::new(AtomicBool::new(true))
}

fn clear_cancel(state: &AppState) {
    if let Ok(mut g) = state.active_cancel.lock() {
        *g = None;
    }
}

fn clear_cancel_if_live(app: &AppHandle, epoch: u64) {
    if still_epoch(app, epoch) {
        if let Some(st) = app.try_state::<AppState>() {
            clear_cancel(&st);
        }
    }
}

fn try_reserve_transfer(state: &AppState) -> Result<(), String> {
    let mut g = state
        .in_flight
        .lock()
        .map_err(|_| "not connected".to_string())?;
    if *g {
        return Err("a transfer is already in progress".to_string());
    }
    *g = true;
    Ok(())
}

fn release_transfer(state: &AppState) {
    if let Ok(mut g) = state.in_flight.lock() {
        *g = false;
    }
}

fn normalize_pairing_code(code: &str) -> Result<String, String> {
    six_digit_join_code(code).ok_or_else(|| "Code must be 6 digits".to_string())
}

/// Crypto/code failures consume the 6-digit brute-force budget. IO drops,
/// joiner cancel, and slowloris stalls do not — otherwise five Cancel taps
/// (or NAT flaps) kill a live invite.
fn handshake_failure_kind(msg: &str) -> HandshakeFailureKind {
    let m = msg.to_ascii_lowercase();
    if m.contains("key confirmation failed")
        || m.contains("spake2 handshake failed")
        || m.contains("bad ephemeral public key")
        || m.contains("invalid ephemeral public key")
        || m.contains("non-contributory ephemeral")
        || m.contains("peer handshake message too short")
    {
        HandshakeFailureKind::BadCode
    } else {
        HandshakeFailureKind::Stall
    }
}

#[derive(Debug, PartialEq, Eq)]
enum HandshakeFailureKind {
    Stall,
    BadCode,
}

fn downloads_root() -> Option<PathBuf> {
    let base = dirs::download_dir().or_else(dirs::home_dir)?;
    Some(base.join("Frostwall Beam"))
}

/// Resolve the directory incoming files land in.
///
/// Honors the user-configured dir when set (the transfer layer creates it on
/// demand); otherwise uses the default `~/Downloads/Frostwall Beam`. `None`
/// if there is no home/Downloads dir — callers must error, not write to cwd.
pub fn effective_download_dir(state: &AppState) -> Option<PathBuf> {
    let configured = state
        .download_dir
        .lock()
        .map(|g| g.clone())
        .unwrap_or(None);
    if let Some(cfg) = configured {
        return Some(PathBuf::from(&cfg));
    }
    downloads_root()
}

fn check_download_dir(p: &Path) -> Result<(), String> {
    if transfer::path_has_symlink_component(p) {
        return Err("download directory must not be a symlink".to_string());
    }
    if is_system_path(p) {
        return Err("refusing a system directory as the download location".to_string());
    }
    Ok(())
}

/// Download dir at recv time (settings can change mid-session).
fn recv_dest_dir(app: &AppHandle) -> Result<PathBuf, String> {
    let dest = match app.try_state::<AppState>() {
        Some(st) => effective_download_dir(&st)
            .ok_or_else(|| "no download directory available".to_string())?,
        None => downloads_root().ok_or_else(|| "no download directory available".to_string())?,
    };
    check_download_dir(&dest)?;
    Ok(dest)
}

/// Reject obviously-dangerous system targets for the download dir.
fn is_system_path(p: &Path) -> bool {
    let c = std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
    if c.parent().is_none() || c == Path::new("/") {
        return true;
    }
    const UNIX_SYS: &[&str] = &[
        "/etc",
        "/usr",
        "/bin",
        "/sbin",
        "/var",
        "/tmp",
        "/private",
        "/dev",
        "/System",
        "/Library",
        "/Applications",
        "/opt",
        "/boot",
        "/proc",
        "/sys",
    ];
    if UNIX_SYS.iter().any(|s| c.starts_with(s)) {
        return true;
    }
    if is_windows_system_path(&c) {
        return true;
    }
    false
}

/// Top-level folder on a volume (`D:\Windows`, `\\?\C:\Program Files`, drive
/// root). A `C:\WINDOWS` prefix check misses other drives and the `\\?\` form
/// `canonicalize` returns. Compiled on all targets so CI can check the
/// first-dir rule with POSIX paths (`/Windows`).
fn is_windows_system_path(c: &Path) -> bool {
    use std::path::Component;
    let mut comps = c.components().peekable();
    while matches!(comps.peek(), Some(Component::Prefix(_))) {
        comps.next();
    }
    match comps.next() {
        Some(Component::RootDir) => {}
        _ => return false,
    }
    match comps.next() {
        None => true,
        Some(Component::Normal(name)) => {
            matches!(
                name.to_string_lossy().to_ascii_uppercase().as_str(),
                "WINDOWS"
                    | "PROGRAM FILES"
                    | "PROGRAM FILES (X86)"
                    | "PROGRAMDATA"
                    | "SYSTEM VOLUME INFORMATION"
            )
        }
        _ => false,
    }
}

/// mDNS instance label: prefer configured device name, else random suffix.
fn mdns_instance_name(state: &AppState) -> String {
    let configured = state
        .device_name
        .lock()
        .ok()
        .and_then(|g| g.clone());
    if let Some(name) = configured {
        let slug: String = name
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() {
                    c.to_ascii_lowercase()
                } else {
                    '-'
                }
            })
            .collect();
        let slug = slug.trim_matches('-');
        if !slug.is_empty() && slug.len() <= 48 {
            return format!("frostwall-{slug}");
        }
    }
    format!("frostwall-{:04}", rand::random::<u16>() % 10000)
}

fn local_display_name(state: &AppState) -> Option<String> {
    state
        .device_name
        .lock()
        .ok()
        .and_then(|g| g.clone())
}

#[derive(Debug, PartialEq, Eq)]
enum PeerNoise {
    Gone,
    Cancel,
    Manifest,
    Stray,
}

enum CollectFail {
    Gone,
    Collision,
}

/// Frames that can arrive while this side is not in `send`/`recv`.
fn interpret_peer_during_idle(
    keys: &SessionKeys,
    frame: Result<Vec<u8>>,
) -> PeerNoise {
    match frame {
        Err(_) => PeerNoise::Gone,
        Ok(bytes) => match transfer::open_control(keys, &bytes) {
            Ok(Message::Cancel) => PeerNoise::Cancel,
            Ok(Message::Manifest(_)) => PeerNoise::Manifest,
            Ok(Message::Chunk(_))
            | Ok(Message::FileEnd(_))
            | Ok(Message::Done)
            | Ok(Message::Accept)
            | Ok(Message::Reject)
            | Ok(Message::Hello(_)) => PeerNoise::Stray,
            Ok(_) => PeerNoise::Stray,
            Err(e) => {
                let msg = e.to_string();
                if msg.contains("expected encrypted control message")
                    || msg.contains("frame too short")
                {
                    PeerNoise::Stray
                } else {
                    PeerNoise::Gone
                }
            }
        },
    }
}

/// Peer-visible decline. `false` = pipe dead — caller must disconnect.
async fn write_reject(conn: &mut Connection, keys: &SessionKeys) -> bool {
    match transfer::seal_control(keys, &Message::Reject) {
        Ok(frame) => transfer::send_or_stall(conn, &frame).await.is_ok(),
        Err(_) => false,
    }
}

#[derive(Debug)]
enum IncomingPick {
    Accept,
    Decline,
    Timeout,
    /// Peer closed the pipe while the user was still looking at the prompt.
    Dropped,
    /// Peer sent `Cancel` instead of waiting for Accept/Reject.
    Cancelled,
}

async fn take_incoming_slot(state: &AppState, epoch: u64) {
    if state.epoch() == epoch {
        state.incoming_decision.lock().await.take();
    }
}

#[cfg(test)]
async fn wait_incoming_decision(state: &AppState, epoch: u64) -> IncomingPick {
    if state.epoch() != epoch {
        return IncomingPick::Decline;
    }
    let (tx, rx) = oneshot::channel();
    {
        let mut slot = state.incoming_decision.lock().await;
        if slot.is_some() {
            return IncomingPick::Decline;
        }
        *slot = Some(tx);
    }
    match tokio::time::timeout(DECISION_TIMEOUT, rx).await {
        Ok(Ok(true)) => IncomingPick::Accept,
        Ok(Ok(false)) | Ok(Err(_)) => IncomingPick::Decline,
        Err(_) => {
            take_incoming_slot(state, epoch).await;
            IncomingPick::Timeout
        }
    }
}

/// Like [`wait_incoming_decision`], but a dead peer / `Cancel` does not sit on
/// the decision UI clock. Stray leftover frames are ignored.
async fn wait_incoming_with_peer(
    state: &AppState,
    epoch: u64,
    conn: &mut Connection,
    keys: &SessionKeys,
) -> IncomingPick {
    if state.epoch() != epoch {
        return IncomingPick::Decline;
    }
    let (tx, rx) = oneshot::channel();
    {
        let mut slot = state.incoming_decision.lock().await;
        if slot.is_some() {
            return IncomingPick::Decline;
        }
        *slot = Some(tx);
    }
    let deadline = tokio::time::Instant::now() + DECISION_TIMEOUT;
    let mut rx = rx;
    loop {
        tokio::select! {
            dec = &mut rx => {
                return match dec {
                    Ok(true) => IncomingPick::Accept,
                    Ok(false) | Err(_) => IncomingPick::Decline,
                };
            }
            frame = conn.recv() => {
                match interpret_peer_during_idle(keys, frame) {
                    PeerNoise::Stray | PeerNoise::Manifest => continue,
                    PeerNoise::Cancel => {
                        take_incoming_slot(state, epoch).await;
                        return IncomingPick::Cancelled;
                    }
                    PeerNoise::Gone => {
                        take_incoming_slot(state, epoch).await;
                        return IncomingPick::Dropped;
                    }
                }
            }
            _ = tokio::time::sleep_until(deadline) => {
                take_incoming_slot(state, epoch).await;
                return IncomingPick::Timeout;
            }
        }
    }
}

fn emit_pairing(app: &AppHandle, on: bool, epoch: u64) {
    if still_epoch(app, epoch) {
        let _ = app.emit(EV_PAIRING, PairingPayload { on, epoch });
    }
}

fn still_epoch(app: &AppHandle, epoch: u64) -> bool {
    app.try_state::<AppState>()
        .is_some_and(|st| st.epoch() == epoch)
}

fn epoch_or_cancel(state: &AppState, epoch: u64) -> Result<(), String> {
    if state.epoch() == epoch {
        Ok(())
    } else {
        Err("pairing cancelled".to_string())
    }
}

fn emit_error_if_live(app: &AppHandle, epoch: u64, msg: String) {
    if still_epoch(app, epoch) {
        let _ = app.emit(EV_ERROR, ErrorPayload { message: msg, epoch });
    }
}

fn emit_disconnect_if_live(app: &AppHandle, epoch: u64) {
    if still_epoch(app, epoch) {
        let _ = app.emit(EV_DISCONNECT, DisconnectPayload { epoch });
    }
}

fn emit_live<T: Serialize + Clone>(app: &AppHandle, epoch: u64, event: &str, payload: T) {
    if still_epoch(app, epoch) {
        let _ = app.emit(event, payload);
    }
}

fn emit_transfer_done(app: &AppHandle, epoch: u64, ok: bool) {
    emit_transfer_finished(app, epoch, ok, None);
}

fn emit_transfer_finished(app: &AppHandle, epoch: u64, ok: bool, error: Option<String>) {
    let error = error.filter(|s| !s.is_empty()).map(|mut s| {
        if s.len() > 240 {
            let mut end = 240;
            while end > 0 && !s.is_char_boundary(end) {
                end -= 1;
            }
            s.truncate(end);
        }
        s
    });
    emit_live(
        app,
        epoch,
        EV_TRANSFER_DONE,
        TransferDonePayload { ok, epoch, error },
    );
}

fn emit_notice(app: &AppHandle, epoch: u64, message: impl Into<String>) {
    emit_live(
        app,
        epoch,
        EV_NOTICE,
        NoticePayload {
            message: message.into(),
            epoch,
        },
    );
}

fn emit_progress(app: &AppHandle, epoch: u64, p: transfer::Progress, direction: &'static str) {
    let percent = if p.total == 0 {
        100.0
    } else {
        p.transferred as f64 * 100.0 / p.total as f64
    };
    emit_live(
        app,
        epoch,
        EV_PROGRESS,
        ProgressPayload {
            transferred: p.transferred,
            total: p.total,
            percent,
            direction,
            epoch,
        },
    );
}

/// Coordinator owns the connection and serializes access: it either runs a
/// local send or services an incoming transfer, never both at once.
async fn run_coordinator(
    app: AppHandle,
    keys: SessionKeys,
    mut conn: Connection,
    mut cmd_rx: mpsc::Receiver<SessionCmd>,
    epoch: u64,
) {
    loop {
        tokio::select! {
            cmd = cmd_rx.recv() => match cmd {
                Some(SessionCmd::Send { paths, reply }) => {
                    let cancel = install_cancel_if_live(&app, epoch);
                    let mut collect_jh = {
                        let cancel = cancel.clone();
                        tokio::task::spawn_blocking(move || {
                            let items = transfer::collect_items_cancellable(&paths, &cancel)?;
                            let tr_items: Vec<TransferItem> = items
                                .iter()
                                .map(|i| TransferItem {
                                    name: i.rel_path.clone(),
                                    size: i.size,
                                })
                                .collect();
                            anyhow::Ok((items, tr_items))
                        })
                    };
                    let collected = loop {
                        tokio::select! {
                            c = &mut collect_jh => break Ok(c),
                            frame = conn.recv() => {
                                match interpret_peer_during_idle(&keys, frame) {
                                    PeerNoise::Stray => continue,
                                    PeerNoise::Cancel => {
                                        cancel.store(true, Ordering::SeqCst);
                                        continue;
                                    }
                                    PeerNoise::Manifest => {
                                        cancel.store(true, Ordering::SeqCst);
                                        break Err(CollectFail::Collision);
                                    }
                                    PeerNoise::Gone => {
                                        cancel.store(true, Ordering::SeqCst);
                                        break Err(CollectFail::Gone);
                                    }
                                }
                            }
                        }
                    };
                    let mut sent = false;
                    let result = match collected {
                        Err(CollectFail::Gone) => {
                            clear_cancel_if_live(&app, epoch);
                            set_in_flight_if_live(&app, epoch, false);
                            let _ = reply.send(Err(anyhow::anyhow!("connection closed by peer")));
                            emit_transfer_done(&app, epoch, false);
                            emit_disconnect_if_live(&app, epoch);
                            break;
                        }
                        Err(CollectFail::Collision) => {
                            let _ = collect_jh.await;
                            // Peer already sent Manifest and is waiting on
                            // Accept/Reject. Dropping the frame left them on
                            // the 6 min decision clock.
                            if write_reject(&mut conn, &keys).await {
                                Err(anyhow::anyhow!("peer started a transfer at the same time"))
                            } else {
                                Err(anyhow::anyhow!("connection closed by peer"))
                            }
                        }
                        Ok(join) => match join {
                            Err(e) => Err(anyhow::anyhow!("collect items: {e}")),
                            Ok(Err(e)) => Err(e),
                            Ok(Ok((items, tr_items))) => {
                            if items.is_empty() {
                                Err(anyhow::anyhow!("nothing to send"))
                            } else {
                            let total: u64 = tr_items.iter().map(|i| i.size).sum();
                            sent = true;
                            let app = app.clone();
                            emit_live(
                                &app,
                                epoch,
                                EV_TRANSFER_START,
                                TransferStartPayload {
                                    direction: "sending",
                                    items: transfer_preview(&tr_items),
                                    total,
                                    file_count: items.len(),
                                    epoch,
                                },
                            );
                            let r = transfer::send(&mut conn, &keys, &items, &mut |p| {
                                emit_progress(&app, epoch, p, "sending")
                            }, &cancel)
                            .await;
                            r
                            }
                            }
                        }
                    };
                    clear_cancel_if_live(&app, epoch);
                    let fail = result.as_ref().err().map(|e| e.to_string());
                    let ok = result.is_ok();
                    let dead = result.as_ref().err().is_some_and(transfer::is_pipe_dead);
                    if result.is_err()
                        && !dead
                        && sent
                        && result.as_ref().err().is_some_and(transfer::needs_abort_drain)
                    {
                        transfer::drain_after_abort(&mut conn).await;
                    }
                    set_in_flight_if_live(&app, epoch, false);
                    let _ = reply.send(result);
                    emit_transfer_finished(&app, epoch, ok, fail);
                    if dead {
                        emit_disconnect_if_live(&app, epoch);
                        break;
                    }
                }
                None => break,
            },
            first = conn.recv() => match first {
                Ok(frame) => {
                    // Validate the manifest BEFORE showing it to the UI or
                    // writing anything (N3): reject unsafe paths/counts/sizes
                    // up front so a malicious transfer neither renders an
                    // attacker-chosen path nor reaches the file layer.
                    let entries = match transfer::open_control(&keys, &frame) {
                        Ok(Message::Manifest(e)) => e,
                        Ok(Message::Cancel)
                        | Ok(Message::Hello(_))
                        | Ok(Message::Accept)
                        | Ok(Message::Reject)
                        | Ok(Message::Done)
                        | Ok(Message::Chunk(_))
                        | Ok(Message::FileEnd(_)) => continue,
                        Ok(_) => {
                            emit_error_if_live(&app, epoch, "session ended".to_string());
                            emit_transfer_done(&app, epoch, false);
                            break;
                        }
                        Err(e) => {
                            let msg = e.to_string();
                            if msg.contains("expected encrypted control message")
                                || msg.contains("frame too short")
                            {
                                continue;
                            }
                            emit_error_if_live(&app, epoch, msg);
                            emit_transfer_done(&app, epoch, false);
                            break;
                        }
                    };
                    if transfer::validate_manifest(&entries).is_err() {
                        if !write_reject(&mut conn, &keys).await {
                            emit_transfer_done(&app, epoch, false);
                            emit_disconnect_if_live(&app, epoch);
                            break;
                        }
                        emit_notice(&app, epoch, "invalid transfer manifest");
                        continue;
                    }
                    if let Err(msg) = recv_dest_dir(&app) {
                        if !write_reject(&mut conn, &keys).await {
                            emit_transfer_done(&app, epoch, false);
                            emit_disconnect_if_live(&app, epoch);
                            break;
                        }
                        emit_notice(&app, epoch, msg);
                        emit_transfer_done(&app, epoch, false);
                        continue;
                    }
                    let items: Vec<TransferItem> = entries
                        .iter()
                        .map(|e| TransferItem { name: e.rel_path.clone(), size: e.size })
                        .collect();
                    let total: u64 = items.iter().map(|i| i.size).sum();
                    let count = items.len();
                    emit_live(
                        &app,
                        epoch,
                        EV_TRANSFER_PENDING,
                        TransferStartPayload {
                            direction: "receiving",
                            items: transfer_preview(&items),
                            total,
                            file_count: count,
                            epoch,
                        },
                    );
                    // Hold the send gate for the whole accept window so a local
                    // drop cannot collide with the incoming transfer.
                    set_in_flight_if_live(&app, epoch, true);
                    let pick = if let Some(st) = app.try_state::<AppState>() {
                        wait_incoming_with_peer(&st, epoch, &mut conn, &keys).await
                    } else {
                        IncomingPick::Decline
                    };
                    match pick {
                        IncomingPick::Accept => {}
                        IncomingPick::Dropped => {
                            set_in_flight_if_live(&app, epoch, false);
                            emit_transfer_done(&app, epoch, false);
                            emit_disconnect_if_live(&app, epoch);
                            break;
                        }
                        IncomingPick::Cancelled => {
                            set_in_flight_if_live(&app, epoch, false);
                            emit_transfer_done(&app, epoch, false);
                            emit_notice(&app, epoch, "transfer cancelled by peer");
                            continue;
                        }
                        IncomingPick::Timeout => {
                            set_in_flight_if_live(&app, epoch, false);
                            if !write_reject(&mut conn, &keys).await {
                                emit_transfer_done(&app, epoch, false);
                                emit_disconnect_if_live(&app, epoch);
                                break;
                            }
                            emit_notice(
                                &app,
                                epoch,
                                "timed out waiting for a transfer decision",
                            );
                            emit_transfer_done(&app, epoch, false);
                            continue;
                        }
                        IncomingPick::Decline => {
                            set_in_flight_if_live(&app, epoch, false);
                            if !write_reject(&mut conn, &keys).await {
                                emit_transfer_done(&app, epoch, false);
                                emit_disconnect_if_live(&app, epoch);
                                break;
                            }
                            emit_transfer_done(&app, epoch, false);
                            continue;
                        }
                    }
                    let dest = match recv_dest_dir(&app) {
                        Ok(d) => d,
                        Err(msg) => {
                            set_in_flight_if_live(&app, epoch, false);
                            if !write_reject(&mut conn, &keys).await {
                                emit_notice(&app, epoch, msg);
                                emit_transfer_done(&app, epoch, false);
                                emit_disconnect_if_live(&app, epoch);
                                break;
                            }
                            emit_notice(&app, epoch, msg);
                            emit_transfer_done(&app, epoch, false);
                            continue;
                        }
                    };
                    match transfer::seal_control(&keys, &Message::Accept) {
                        Ok(accept) => {
                            if let Err(e) = transfer::send_or_stall(&mut conn, &accept).await {
                                emit_error_if_live(&app, epoch, e.to_string());
                                emit_transfer_done(&app, epoch, false);
                                if transfer::is_pipe_dead(&e) {
                                    emit_disconnect_if_live(&app, epoch);
                                }
                                break;
                            }
                        }
                        Err(e) => {
                            emit_error_if_live(&app, epoch, e.to_string());
                            emit_transfer_done(&app, epoch, false);
                            break;
                        }
                    }
                    let cancel = install_cancel_if_live(&app, epoch);
                    let app = app.clone();
                    let dest = dest.clone();
                    emit_live(
                        &app,
                        epoch,
                        EV_TRANSFER_START,
                        TransferStartPayload {
                            direction: "receiving",
                            items: transfer_preview(&items),
                            total,
                            file_count: count,
                            epoch,
                        },
                    );
                    let result = transfer::recv_from_first(
                        &mut conn,
                        &keys,
                        &dest,
                        &mut |p| emit_progress(&app, epoch, p, "receiving"),
                        frame,
                        &cancel,
                    )
                    .await;
                    clear_cancel_if_live(&app, epoch);
                    set_in_flight_if_live(&app, epoch, false);
                    if let Err(e) = result {
                        let msg = e.to_string();
                        emit_transfer_finished(&app, epoch, false, Some(msg.clone()));
                        if transfer::is_pipe_dead(&e) {
                            emit_disconnect_if_live(&app, epoch);
                            break;
                        }
                        if !transfer::is_local_cancel(&e) {
                            emit_notice(&app, epoch, msg);
                        }
                        transfer::drain_after_abort(&mut conn).await;
                        continue;
                    }
                    emit_transfer_done(&app, epoch, true);
                    emit_live(
                        &app,
                        epoch,
                        EV_RECEIVED,
                        ReceivedPayload {
                            dest: dest.to_string_lossy().to_string(),
                            epoch,
                        },
                    );
                }
                Err(_) => {
                    emit_disconnect_if_live(&app, epoch);
                    break;
                }
            },
        }
    }

    // Drain any queued sends so their callers get a clear "session ended"
    // error instead of the misleading "coordinator dropped".
    while let Ok(SessionCmd::Send { reply, .. }) = cmd_rx.try_recv() {
        let _ = reply.send(Err(anyhow::anyhow!(
            "session ended (peer disconnected or transfer cancelled)"
        )));
    }
    // Drop our handle only if this epoch still owns the slot, then clear.
    // A newer host/join already bumped the epoch — do not abort it.
    if let Some(st) = app.try_state::<AppState>() {
        {
            let mut slot = st.coordinator_task.lock().await;
            if st.epoch() == epoch {
                let _ = slot.take();
            }
        }
        if still_epoch(&app, epoch) {
            st.clear().await;
        }
    }
}

/// Install a freshly-paired session: store its liveness key + command channel
/// in app state, emit the paired event, and launch the coordinator.
async fn establish_session(app: &AppHandle, session: Session, epoch: u64) {
    if !still_epoch(app, epoch) {
        return;
    }
    let (mut conn, keys) = session.into_parts();
    let liveness = keys.liveness_key;
    let (tx, rx) = mpsc::channel::<SessionCmd>(8);
    let (mut peer_name, local_name) = {
        let st = app.state::<AppState>();
        if st.epoch() != epoch {
            return;
        }
        let peer = st.peer_display_name.lock().await.take();
        if st.epoch() != epoch {
            *st.peer_display_name.lock().await = peer;
            return;
        }
        let local = local_display_name(&st);
        (peer, local)
    };
    match transfer::exchange_hello(&mut conn, &keys, local_name.as_deref()).await {
        Ok(Some(hello)) => peer_name = Some(hello),
        Ok(None) => {}
        Err(e) => {
            emit_error_if_live(app, epoch, e.to_string());
            if let Some(st) = app.try_state::<AppState>() {
                if st.epoch() == epoch {
                    // Do not abort this pairing task — we are running on it.
                    let _ = st.pairing_task.lock().await.take();
                    st.clear().await;
                }
            }
            return;
        }
    }
    if !still_epoch(app, epoch) {
        return;
    }
    {
        let st = app.state::<AppState>();
        if st.epoch() != epoch {
            return;
        }
        *st.liveness_key.lock().await = Some(liveness);
        if st.epoch() != epoch {
            *st.liveness_key.lock().await = None;
            return;
        }
        *st.cmd_tx.lock().await = Some(tx);
        if st.epoch() != epoch {
            *st.cmd_tx.lock().await = None;
            *st.liveness_key.lock().await = None;
            return;
        }
        // Leave pairing_task to the host/join task so a stale write cannot
        // `None` a newer session's abort handle.
    }
    emit_live(
        app,
        epoch,
        EV_PAIRED,
        PairedPayload {
            peer_name,
            local_name,
            epoch,
        },
    );
    if !still_epoch(app, epoch) {
        return;
    }
    let app_for_coord = app.clone();
    let handle = async_runtime::spawn(async move {
        run_coordinator(app_for_coord, keys, conn, rx, epoch).await;
    });
    if let Some(st) = app.try_state::<AppState>() {
        let mut slot = st.coordinator_task.lock().await;
        if st.epoch() == epoch {
            *slot = Some(handle);
        } else {
            drop(slot);
            handle.abort();
        }
    } else {
        handle.abort();
    }
}

/// Generate a fresh 6-digit pairing code (host side).
#[tauri::command]
pub async fn generate_code() -> String {
    session::generate_pairing_code()
}

/// Host: advertise on the LAN, accept one peer, run the SPAKE2 handshake.
///
/// Binds to the discovered LAN interface (not 0.0.0.0) so the listener is
/// not reachable from VPN/Docker/public-Wi-Fi interfaces. Accepts in a loop
/// and aborts after [`MAX_PAIRING_ATTEMPTS`] failed handshakes — bounding
/// online brute-force of the 6-digit code.
#[tauri::command]
pub async fn host_start(app: AppHandle, state: State<'_, AppState>, code: String) -> Result<u64, String> {
    let code = normalize_pairing_code(&code)?;
    state.clear().await;
    let epoch = state.epoch();

    let ip = discovery::local_lan_ip()
        .ok_or_else(|| {
            "no LAN interface found — connect to the same network or use Internet mode".to_string()
        })?;
    let listener = transport::bind_to(ip, 0).await.map_err(|e| e.to_string())?;
    epoch_or_cancel(&state, epoch)?;
    let port = listener.local_addr().map_err(|e| e.to_string())?.port();

    let mut disc = Discovery::new().map_err(|e| e.to_string())?;
    let instance = mdns_instance_name(&state);
    disc.advertise(&instance, ip, port).map_err(|e| e.to_string())?;
    epoch_or_cancel(&state, epoch)?;

    let app = app.clone();
    let handle = async_runtime::spawn(async move {
        // Accept in a loop so a stalled/failed handshake does not consume the
        // only slot; abort after too many wrong-code failures (online brute-force bound).
        let mut bad_code_attempts = 0u32;
        let mut stall_attempts = 0u32;
        loop {
            if !still_epoch(&app, epoch) {
                break;
            }
            let conn = match transport::accept(&listener).await {
                Ok(c) => c,
                Err(e) => {
                    emit_error_if_live(&app, epoch, e.to_string());
                    break;
                }
            };
            emit_pairing(&app, true, epoch);
            match session::host_handshake(conn, &code).await {
                Ok(session) => {
                    drop(disc); // stop advertising once paired
                    if still_epoch(&app, epoch) {
                        establish_session(&app, session, epoch).await;
                    }
                    break;
                }
                Err(e) => {
                    emit_pairing(&app, false, epoch);
                    if !still_epoch(&app, epoch) {
                        break;
                    }
                    let msg = e.to_string();
                    match handshake_failure_kind(&msg) {
                        HandshakeFailureKind::Stall => {
                            stall_attempts += 1;
                            if stall_attempts >= MAX_STALL_ATTEMPTS {
                                emit_error_if_live(
                                    &app,
                                    epoch,
                                    "too many stalled pairing attempts; please regenerate the code"
                                        .to_string(),
                                );
                                break;
                            }
                            continue;
                        }
                        HandshakeFailureKind::BadCode => {
                            bad_code_attempts += 1;
                            if bad_code_attempts >= MAX_PAIRING_ATTEMPTS {
                                emit_error_if_live(
                                    &app,
                                    epoch,
                                    "too many failed pairing attempts; please regenerate the code".to_string(),
                                );
                                break;
                            }
                        }
                    }
                }
            }
        }
    });
    *state.pairing_task.lock().await = Some(handle);
    if let Err(e) = epoch_or_cancel(&state, epoch) {
        state.abort_pairing().await;
        state.cleanup_internet().await;
        return Err(e);
    }

    Ok(epoch)
}

/// Host: same pairing flow as [`host_start`], but reachable across
/// different networks via `iroh`. Emits a shareable iroh ticket so the
/// joiner needs no mailbox. If a mailbox URL is configured, the 6-digit
/// code is also registered there as a convenience.
#[tauri::command]
pub async fn host_start_internet(
    app: AppHandle,
    state: State<'_, AppState>,
    code: String,
) -> Result<InvitePayload, String> {
    let code = normalize_pairing_code(&code)?;
    state.clear().await;
    let epoch = state.epoch();

    let mailbox_url = optional_mailbox_url(&state).await;
    let ep = internet::host_endpoint().await.map_err(|e| e.to_string())?;
    epoch_or_cancel(&state, epoch)?;
    let endpoint_id = internet::endpoint_id_string(&ep);
    let (mut relays, mut ips) = internet::shareable_hints(&ep);

    let host_name = local_display_name(&state);
    let mut mailbox = mailbox_url.map(internet::Mailbox::new);
    let mut code = code;
    let mut token: Option<String> = None;
    let mut mailbox_ok = false;
    if let Some(mb) = mailbox.as_ref() {
        let reg = internet::register_or_rotate(
            mb,
            code,
            &endpoint_id,
            host_name.as_deref(),
            &relays,
            &ips,
            |c| internet::make_invite_named(&ep, c, host_name.as_deref()),
        )
        .await;
        code = reg.code;
        token = reg.token;
        mailbox_ok = reg.ok;
    }
    if state.epoch() != epoch {
        if let Some(mb) = mailbox.as_ref() {
            mb.unregister(&code, token.as_deref()).await;
        }
        return Err("pairing cancelled".to_string());
    }

    // Mailbox HTTP can outlast the first hint snapshot; re-read before
    // the joiner copies a ticket or looks up 6 digits.
    (relays, ips) = internet::shareable_hints(&ep);
    let invite = internet::make_invite_named(&ep, &code, host_name.as_deref());
    let has_relay = remote_dialable(&relays, &ips);
    if let (Some(mb), Some(tok)) = (mailbox.as_ref(), token.as_deref()) {
        match mb
            .refresh_hints(&code, tok, host_name.as_deref(), &relays, &ips)
            .await
        {
            Ok(()) => {}
            Err(e) if internet::mailbox_slot_lost(&e) => {
                mailbox_ok = false;
                token = None;
            }
            Err(_) => {}
        }
    }
    if state.epoch() != epoch {
        if let Some(mb) = mailbox.as_ref() {
            mb.unregister(&code, token.as_deref()).await;
        }
        return Err("pairing cancelled".to_string());
    }

    let payload = InvitePayload {
        invite: invite.clone(),
        code: code.clone(),
        has_relay,
        mailbox_ok,
        epoch,
    };
    emit_live(&app, epoch, EV_INVITE, payload.clone());

    *state.internet_cleanup.lock().await = Some(InternetCleanup {
        mailbox: mailbox.clone(),
        code: code.clone(),
        token: token.clone(),
    });
    if state.epoch() != epoch {
        state.cleanup_internet().await;
        return Err("pairing cancelled".to_string());
    }

    let hosting_invite = Arc::new(AtomicBool::new(true));
    let app = app.clone();
    let handle = async_runtime::spawn(async move {
        let host_name_keep = host_name.clone();
        let endpoint_id_keep = endpoint_id.clone();
        let _refresh = if !relays.is_empty() {
            let _ = (host_name, endpoint_id);
            None
        } else {
            Some(AbortOnDrop(async_runtime::spawn({
                let ep = ep.clone();
                let app = app.clone();
                let code = code.clone();
                let mailbox = mailbox.clone();
                let token = token.clone();
                let host_name = host_name;
                let endpoint_id = endpoint_id;
                let hosting_invite = hosting_invite.clone();
                async move {
                    if !internet::wait_for_shareable_relay(&ep, RELAY_REFRESH_WAIT).await {
                        return;
                    }
                    if !hosting_invite.load(Ordering::SeqCst) {
                        return;
                    }
                    let (relays, ips) = internet::shareable_hints(&ep);
                    if relays.is_empty() {
                        return;
                    }
                    let invite = internet::make_invite_named(&ep, &code, host_name.as_deref());
                    let mut mailbox_ok = mailbox_ok;
                    if let Some(mb) = mailbox.as_ref() {
                        let tok = if let Some(st) = app.try_state::<AppState>() {
                            st.internet_cleanup
                                .lock()
                                .await
                                .as_ref()
                                .and_then(|c| c.token.clone())
                        } else {
                            token.clone()
                        };
                        let mut published = false;
                        if let Some(tok) = tok.as_deref() {
                            match mb
                                .refresh_hints(
                                    &code,
                                    tok,
                                    host_name.as_deref(),
                                    &relays,
                                    &ips,
                                )
                                .await
                            {
                                Ok(()) => published = true,
                                Err(e) if !internet::mailbox_slot_lost(&e) => {
                                    // 429/network: slot still ours. Ticket has the new relay.
                                    published = true;
                                }
                                Err(_) => {}
                            }
                        }
                        if !published {
                            match mb
                                .register(
                                    &code,
                                    &endpoint_id,
                                    host_name.as_deref(),
                                    &relays,
                                    &ips,
                                )
                                .await
                            {
                                Ok(new_tok) => {
                                    if !hosting_invite.load(Ordering::SeqCst)
                                        || !still_epoch(&app, epoch)
                                    {
                                        mb.unregister(&code, Some(&new_tok)).await;
                                        return;
                                    }
                                    published = true;
                                    if let Some(st) = app.try_state::<AppState>() {
                                        if let Some(c) =
                                            st.internet_cleanup.lock().await.as_mut()
                                        {
                                            c.token = Some(new_tok);
                                        }
                                    }
                                }
                                Err(_) => published = false,
                            }
                        }
                        mailbox_ok = published;
                    }
                    if !hosting_invite.load(Ordering::SeqCst) || !still_epoch(&app, epoch) {
                        return;
                    }
                    let _ = app.emit(
                        EV_INVITE,
                        InvitePayload {
                            invite,
                            code,
                            has_relay: true,
                            mailbox_ok,
                            epoch,
                        },
                    );
                }
            })))
        };
        let _mailbox_keep = mailbox.as_ref().map(|mb| {
            AbortOnDrop(async_runtime::spawn({
                let mb = mb.clone();
                let app = app.clone();
                let code = code.clone();
                let ep = ep.clone();
                let hosting_invite = hosting_invite.clone();
                let host_name = host_name_keep;
                let endpoint_id = endpoint_id_keep;
                async move {
                    loop {
                        tokio::time::sleep(MAILBOX_REFRESH_WAIT).await;
                        if !hosting_invite.load(Ordering::SeqCst) || !still_epoch(&app, epoch) {
                            return;
                        }
                        let tok = if let Some(st) = app.try_state::<AppState>() {
                            if st.epoch() != epoch {
                                return;
                            }
                            st.internet_cleanup
                                .lock()
                                .await
                                .as_ref()
                                .and_then(|c| c.token.clone())
                        } else {
                            None
                        };
                        let Some(tok) = tok else {
                            continue;
                        };
                        match mb.refresh(&code, &tok).await {
                            Ok(()) => continue,
                            Err(e) if internet::mailbox_slot_lost(&e) => {}
                            Err(_) => continue,
                        }
                        if !hosting_invite.load(Ordering::SeqCst) || !still_epoch(&app, epoch) {
                            return;
                        }
                        let (relays, ips) = internet::shareable_hints(&ep);
                        match mb
                            .register(
                                &code,
                                &endpoint_id,
                                host_name.as_deref(),
                                &relays,
                                &ips,
                            )
                            .await
                        {
                            Ok(new_tok) => {
                                if !hosting_invite.load(Ordering::SeqCst) || !still_epoch(&app, epoch)
                                {
                                    mb.unregister(&code, Some(&new_tok)).await;
                                    return;
                                }
                                if let Some(st) = app.try_state::<AppState>() {
                                    if let Some(c) = st.internet_cleanup.lock().await.as_mut() {
                                        c.token = Some(new_tok);
                                    }
                                }
                            }
                            Err(e) if internet::mailbox_code_taken(&e) => {
                                // Slot stolen. Do not rotate SPAKE2: the live
                                // ticket already embeds these digits. A new
                                // code cannot un-steal the old 6-digit lookup.
                                if !hosting_invite.load(Ordering::SeqCst) || !still_epoch(&app, epoch)
                                {
                                    return;
                                }
                                let invite =
                                    internet::make_invite_named(&ep, &code, host_name.as_deref());
                                let (relays, ips) = internet::shareable_hints(&ep);
                                let has_relay = remote_dialable(&relays, &ips);
                                emit_live(
                                    &app,
                                    epoch,
                                    EV_INVITE,
                                    InvitePayload {
                                        invite,
                                        code: code.clone(),
                                        has_relay,
                                        mailbox_ok: false,
                                        epoch,
                                    },
                                );
                            }
                            Err(_) => {}
                        }
                    }
                }
            }))
        });
        let mut bad_code_attempts = 0u32;
        let mut stall_attempts = 0u32;
        loop {
            if !still_epoch(&app, epoch) {
                break;
            }
            let conn = match internet::accept_one(&ep).await {
                Ok(c) => c,
                Err(e) if internet::accept_retryable(&e) => continue,
                Err(e) => {
                    emit_error_if_live(&app, epoch, e.to_string());
                    break;
                }
            };
            emit_pairing(&app, true, epoch);
            match session::host_handshake(conn, &code).await {
                Ok(session) => {
                    hosting_invite.store(false, Ordering::SeqCst);
                    if still_epoch(&app, epoch) {
                        if let Some(st) = app.try_state::<AppState>() {
                            st.cleanup_internet().await;
                        }
                        establish_session(&app, session, epoch).await;
                    }
                    break;
                }
                Err(e) => {
                    emit_pairing(&app, false, epoch);
                    if !still_epoch(&app, epoch) {
                        break;
                    }
                    let msg = e.to_string();
                    match handshake_failure_kind(&msg) {
                        HandshakeFailureKind::Stall => {
                            stall_attempts += 1;
                            if stall_attempts >= MAX_STALL_ATTEMPTS {
                                emit_error_if_live(
                                    &app,
                                    epoch,
                                    "too many stalled pairing attempts; please regenerate the code"
                                        .to_string(),
                                );
                                break;
                            }
                            continue;
                        }
                        HandshakeFailureKind::BadCode => {
                            bad_code_attempts += 1;
                            if bad_code_attempts >= MAX_PAIRING_ATTEMPTS {
                                emit_error_if_live(
                                    &app,
                                    epoch,
                                    "too many failed pairing attempts; please regenerate the code".to_string(),
                                );
                                break;
                            }
                        }
                    }
                }
            }
        }
        hosting_invite.store(false, Ordering::SeqCst);
        if let Some(st) = app.try_state::<AppState>() {
            st.cleanup_internet().await;
        } else if let Some(mb) = mailbox.take() {
            mb.unregister(&code, token.as_deref()).await;
        }
    });
    *state.pairing_task.lock().await = Some(handle);
    if let Err(e) = epoch_or_cancel(&state, epoch) {
        state.abort_pairing().await;
        state.cleanup_internet().await;
        return Err(e);
    }

    Ok(payload)
}

/// Discover Frostwall hosts on the LAN (for multi-host selection).
/// Cancel/`clear()` bumps `session_epoch` so the blocking browse exits early.
#[tauri::command]
pub async fn discover_peers(state: State<'_, AppState>) -> Result<Vec<DiscoveredPeer>, String> {
    let epoch = state.epoch();
    let atom = Arc::clone(&state.session_epoch);
    tokio::task::spawn_blocking(move || {
        discovery::browse_peers_while(Duration::from_secs(5), || {
            atom.load(Ordering::SeqCst) == epoch
        })
        .map_err(|e| e.to_string())
        .map(|peers| {
            peers
                .into_iter()
                .map(|(display_name, ip, port)| DiscoveredPeer {
                    display_name,
                    address: ip.to_string(),
                    port,
                })
                .collect()
        })
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Joiner: connect to a specific host and run the SPAKE2 handshake.
#[tauri::command]
pub async fn join_peer(
    app: AppHandle,
    state: State<'_, AppState>,
    code: String,
    address: String,
    port: u16,
    display_name: Option<String>,
) -> Result<u64, String> {
    let code = normalize_pairing_code(&code)?;
    state.clear().await;
    let epoch = state.epoch();
    *state.peer_display_name.lock().await = display_name;

    let ip: IpAddr = address
        .parse()
        .map_err(|_| format!("invalid address: {address}"))?;
    let addr = SocketAddr::new(ip, port);

    let app = app.clone();
    let handle = async_runtime::spawn(async move {
        if !still_epoch(&app, epoch) {
            return;
        }
        let conn = match transport::connect(addr).await {
            Ok(c) => c,
            Err(e) => {
                emit_error_if_live(&app, epoch, e.to_string());
                return;
            }
        };
        if !still_epoch(&app, epoch) {
            return;
        }
        emit_pairing(&app, true, epoch);
        match session::joiner_handshake(conn, &code).await {
            Ok(session) => {
                if still_epoch(&app, epoch) {
                    establish_session(&app, session, epoch).await;
                }
            }
            Err(e) => {
                emit_error_if_live(&app, epoch, e.to_string());
            }
        }
    });
    *state.pairing_task.lock().await = Some(handle);
    if let Err(e) = epoch_or_cancel(&state, epoch) {
        state.abort_pairing().await;
        state.cleanup_internet().await;
        return Err(e);
    }

    Ok(epoch)
}

/// Mailbox join: 6 digits after stripping whitespace (`123 456`, trailing newline).
fn six_digit_join_code(input: &str) -> Option<String> {
    let compact: String = input.chars().filter(|c| !c.is_whitespace()).collect();
    (compact.len() == 6 && compact.chars().all(|c| c.is_ascii_digit())).then_some(compact)
}

/// Joiner: dial a host on another network. Prefer a full invite (iroh
/// ticket or legacy `fwb2-…`). A bare 6-digit code still works if a
/// mailbox URL is configured.
#[tauri::command]
pub async fn join_internet(app: AppHandle, state: State<'_, AppState>, invite: String) -> Result<u64, String> {
    state.clear().await;
    let epoch = state.epoch();

    let mailbox_url = optional_mailbox_url(&state).await;
    let app = app.clone();
    let handle = async_runtime::spawn(async move {
        if !still_epoch(&app, epoch) {
            return;
        }
        let parsed = match internet::parse_invite(&invite) {
            Ok(p) => {
                if let Some(st) = app.try_state::<AppState>() {
                    if p.device_name.is_some() {
                        *st.peer_display_name.lock().await = p.device_name.clone();
                    }
                }
                p
            }
            Err(e) => {
                if internet::looks_like_remote_invite(&invite) {
                    emit_error_if_live(&app, epoch, e.to_string());
                    return;
                }
                let Some(digits) = six_digit_join_code(&invite) else {
                    emit_error_if_live(
                        &app,
                        epoch,
                        if mailbox_url.is_some() {
                            "paste the invite or enter the 6-digit code".to_string()
                        } else {
                            "paste the invite from the other device".to_string()
                        },
                    );
                    return;
                };
                let Some(url) = mailbox_url else {
                    emit_error_if_live(
                        &app,
                        epoch,
                        "paste the invite from the other device".to_string(),
                    );
                    return;
                };
                let mailbox = internet::Mailbox::new(url);
                match mailbox.lookup(&digits).await {
                    Ok(peer) => {
                        if !still_epoch(&app, epoch) {
                            return;
                        }
                        if let Some(st) = app.try_state::<AppState>() {
                            *st.peer_display_name.lock().await =
                                crate::protocol::sanitize_display_name(peer.device_name.as_deref());
                        }
                        internet::ParsedInvite::from_mailbox(
                            peer.endpoint_id,
                            digits,
                            peer.relays,
                            peer.ips,
                        )
                    }
                    Err(e) => {
                        emit_error_if_live(&app, epoch, e.to_string());
                        return;
                    }
                }
            }
        };
        if !still_epoch(&app, epoch) {
            return;
        }
        let ep = match internet::join_endpoint().await {
            Ok(ep) => ep,
            Err(e) => {
                emit_error_if_live(&app, epoch, e.to_string());
                return;
            }
        };
        if !still_epoch(&app, epoch) {
            return;
        }
        let conn = match internet::connect_to(&ep, &parsed).await {
            Ok(c) => c,
            Err(e) => {
                emit_error_if_live(&app, epoch, e.to_string());
                return;
            }
        };
        if !still_epoch(&app, epoch) {
            return;
        }
        emit_pairing(&app, true, epoch);
        match session::joiner_handshake(conn, &parsed.code).await {
            Ok(session) => {
                if still_epoch(&app, epoch) {
                    establish_session(&app, session, epoch).await;
                }
            }
            Err(e) => {
                emit_error_if_live(&app, epoch, e.to_string());
            }
        }
    });
    *state.pairing_task.lock().await = Some(handle);
    if let Err(e) = epoch_or_cancel(&state, epoch) {
        state.abort_pairing().await;
        state.cleanup_internet().await;
        return Err(e);
    }

    Ok(epoch)
}

/// Send a list of files/folders to the peer.
#[tauri::command]
pub async fn send_files(state: State<'_, AppState>, paths: Vec<String>) -> Result<(), String> {
    try_reserve_transfer(&state)?;
    let _ = install_cancel(&state);
    let tx = state
        .cmd_tx
        .lock()
        .await
        .clone()
        .ok_or_else(|| {
            release_transfer(&state);
            clear_cancel(&state);
            "not connected".to_string()
        })?;
    let paths: Vec<PathBuf> = paths.into_iter().map(PathBuf::from).collect();
    let (reply_tx, reply_rx) = oneshot::channel();
    if tx
        .send(SessionCmd::Send {
            paths,
            reply: reply_tx,
        })
        .await
        .is_err()
    {
        release_transfer(&state);
        clear_cancel(&state);
        return Err("coordinator stopped".to_string());
    }
    match reply_rx.await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => Err(e.to_string()),
        Err(_) => {
            release_transfer(&state);
            clear_cancel(&state);
            Err("session ended (peer disconnected or transfer cancelled)".to_string())
        }
    }
}

/// Current rotating liveness code, or None if not connected.
#[tauri::command]
pub async fn current_liveness_code(state: State<'_, AppState>) -> Result<Option<String>, String> {
    let guard = state.liveness_key.lock().await;
    let key = match &*guard {
        Some(k) => k,
        None => return Ok(None),
    };
    Ok(Some(liveness::current_code(key, now_unix())))
}

/// Cancel the in-flight transfer without disconnecting the session.
#[tauri::command]
pub async fn cancel_transfer(state: State<'_, AppState>) -> Result<(), String> {
    let in_flight = state
        .in_flight
        .lock()
        .map(|g| *g)
        .unwrap_or(false);
    if !in_flight {
        return Err("no transfer in progress".to_string());
    }
    let flag = state
        .active_cancel
        .lock()
        .map_err(|_| "no transfer in progress".to_string())?
        .clone()
        .ok_or_else(|| "no transfer in progress".to_string())?;
    flag.store(true, Ordering::SeqCst);
    Ok(())
}

/// Disconnect and tear down the current session, or cancel an in-progress
/// pairing (host/join) that has not yet connected.
#[tauri::command]
pub async fn disconnect(state: State<'_, AppState>) -> Result<(), String> {
    state.abort_pairing().await;
    state.trigger_cancel();
    if let Some(tx) = state.incoming_decision.lock().await.take() {
        let _ = tx.send(false);
    }
    // Dropping our sender makes the coordinator's cmd channel close => it exits.
    *state.cmd_tx.lock().await = None;
    state.clear().await;
    Ok(())
}

/// Accept or reject a pending incoming transfer (after manifest review).
#[tauri::command]
pub async fn respond_incoming_transfer(
    state: State<'_, AppState>,
    accept: bool,
) -> Result<(), String> {
    let tx = state
        .incoming_decision
        .lock()
        .await
        .take()
        .ok_or_else(|| "no pending transfer".to_string())?;
    tx.send(accept)
        .map_err(|_| "transfer decision already handled".to_string())
}

/// Read current user config (mirrors what's persisted on disk).
#[tauri::command]
pub async fn get_config(state: State<'_, AppState>) -> Result<ConfigPayload, String> {
    let download_dir = state
        .download_dir
        .lock()
        .map(|g| g.clone())
        .ok()
        .flatten();
    let device_name = state
        .device_name
        .lock()
        .map(|g| g.clone())
        .ok()
        .flatten();
    let mailbox_url = state
        .mailbox_url
        .lock()
        .map(|g| g.clone())
        .ok()
        .flatten()
        .filter(|u| crate::config::mailbox_url_allowed(u));
    let remote_available = crate::config::remote_mailbox_configured(&mailbox_url);
    Ok(ConfigPayload {
        download_dir,
        device_name,
        mailbox_url,
        remote_available,
    })
}

/// Set the download directory. Validates the path (real directory, not a
/// symlink, not a system path), persists to disk under the config lock, and
/// updates in-memory state. Returns the effective directory now in use.
#[tauri::command]
pub async fn set_download_dir(
    state: State<'_, AppState>,
    path: String,
) -> Result<String, String> {
    let p = PathBuf::from(&path);
    // Reject system / symlink paths *before* create_dir_all so we do not
    // mkdir inside /etc when the picker path is `/etc/frostwall`.
    if transfer::path_has_symlink_component(&p) {
        return Err("download directory must not be a symlink".to_string());
    }
    if is_system_path(&p) {
        return Err("refusing a system directory as the download location".to_string());
    }
    transfer::mkdir_abs_nofollow(&p)
        .map_err(|e| format!("could not access or create directory {path}: {e}"))?;
    check_download_dir(&p)?;
    let meta = std::fs::symlink_metadata(&p)
        .map_err(|e| format!("could not read directory {path}: {e}"))?;
    if transfer::is_link_like_path(&p) {
        return Err("download directory must not be a symlink".to_string());
    }
    if !meta.is_dir() {
        return Err("path is not a directory".to_string());
    }
    // Persist atomically (config_lock serializes load→modify→save).
    let _guard = state.config_lock.lock();
    if let Ok(mut g) = state.download_dir.lock() {
        *g = Some(path.clone());
    }
    let mut cfg = crate::config::load();
    cfg.download_dir = Some(path.clone());
    crate::config::save(&cfg).map_err(|e| format!("failed to persist config: {e}"))?;
    drop(_guard);
    Ok(path)
}

/// Set the device name. Rejects empty/whitespace-only names. Persists to disk
/// under the config lock so it cannot race a concurrent set_download_dir.
#[tauri::command]
pub async fn set_device_name(state: State<'_, AppState>, name: String) -> Result<(), String> {
    let value = stored_device_name(&name)?;
    let _guard = state.config_lock.lock();
    if let Ok(mut g) = state.device_name.lock() {
        *g = Some(value.clone());
    }
    let mut cfg = crate::config::load();
    cfg.device_name = Some(value);
    crate::config::save(&cfg).map_err(|e| format!("failed to persist config: {e}"))?;
    drop(_guard);
    Ok(())
}

fn stored_device_name(name: &str) -> Result<String, String> {
    crate::protocol::sanitize_display_name(Some(name))
        .ok_or_else(|| "device name must not be empty".to_string())
}

/// Set (or, if blank, clear) the optional mailbox URL. Remote pairing
/// defaults to a shareable invite; a mailbox only enables 6-digit lookup.
#[tauri::command]
pub async fn set_mailbox_url(state: State<'_, AppState>, url: String) -> Result<(), String> {
    let trimmed = url.trim();
    let value = if trimmed.is_empty() {
        None
    } else if crate::config::mailbox_url_allowed(trimmed) {
        Some(trimmed.trim_end_matches('/').to_string())
    } else {
        return Err(
            "mailbox URL must use https:// (http://127.0.0.1 or http://localhost only in debug builds)"
                .to_string(),
        );
    };
    let _guard = state.config_lock.lock();
    if let Ok(mut g) = state.mailbox_url.lock() {
        *g = value.clone();
    }
    let mut cfg = crate::config::load();
    cfg.mailbox_url = value;
    crate::config::save(&cfg).map_err(|e| format!("failed to persist config: {e}"))?;
    drop(_guard);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn downloads_root_is_some() {
        assert!(downloads_root().is_some());
        assert_ne!(
            downloads_root().as_deref(),
            Some(std::path::Path::new(".")),
            "default dest must not be process cwd"
        );
        let st = AppState::new();
        let dest = effective_download_dir(&st).expect("home or Downloads");
        assert_ne!(dest, PathBuf::from("."));
        assert!(dest.ends_with("Frostwall Beam"));
    }

    #[test]
    fn stored_device_name_caps_and_strips() {
        assert_eq!(stored_device_name("  Mac\u{0007}  ").unwrap(), "Mac");
        assert_eq!(
            stored_device_name(&"n".repeat(80)).unwrap().len(),
            crate::protocol::MAX_DISPLAY_NAME
        );
        assert!(stored_device_name("   ").is_err());
        assert!(stored_device_name("\u{0007}").is_err());
    }

    #[test]
    fn handshake_failure_kind_drops_are_stalls_not_bad_code() {
        assert_eq!(
            handshake_failure_kind("connection closed by peer"),
            HandshakeFailureKind::Stall
        );
        assert_eq!(
            handshake_failure_kind("recv frame: connection reset"),
            HandshakeFailureKind::Stall
        );
        assert_eq!(
            handshake_failure_kind("send frame: broken pipe"),
            HandshakeFailureKind::Stall
        );
        assert_eq!(
            handshake_failure_kind("handshake timed out (peer stalled)"),
            HandshakeFailureKind::Stall
        );
        assert_eq!(
            handshake_failure_kind("key confirmation failed (wrong code or MITM)"),
            HandshakeFailureKind::BadCode
        );
        assert_eq!(
            handshake_failure_kind("SPAKE2 handshake failed (malformed peer message)"),
            HandshakeFailureKind::BadCode
        );
        assert_eq!(
            handshake_failure_kind("peer handshake message too short"),
            HandshakeFailureKind::BadCode
        );
        assert_eq!(
            handshake_failure_kind("invalid ephemeral public key"),
            HandshakeFailureKind::BadCode
        );
        assert_eq!(
            handshake_failure_kind("bad ephemeral public key length"),
            HandshakeFailureKind::BadCode
        );
        assert_eq!(
            handshake_failure_kind("non-contributory ephemeral exchange"),
            HandshakeFailureKind::BadCode
        );
    }

    #[test]
    fn remote_dialable_accepts_public_ip_without_relay() {
        assert!(!remote_dialable(&[], &[]));
        assert!(remote_dialable(&["https://relay.example/".into()], &[]));
        assert!(remote_dialable(&[], &["203.0.113.9:4242".into()]));
        assert!(remote_dialable(
            &["https://relay.example/".into()],
            &["203.0.113.9:4242".into()]
        ));
    }

    #[test]
    fn six_digit_join_code_strips_whitespace() {
        assert_eq!(six_digit_join_code("123456").as_deref(), Some("123456"));
        assert_eq!(six_digit_join_code(" 123 456 \n").as_deref(), Some("123456"));
        assert_eq!(six_digit_join_code("1234567"), None);
        assert_eq!(six_digit_join_code("fwb2-x"), None);
        assert_eq!(six_digit_join_code(""), None);
        assert_eq!(normalize_pairing_code(" 123 456 ").as_deref(), Ok("123456"));
        assert!(normalize_pairing_code("12345").is_err());
    }

    #[test]
    fn is_system_path_rejects_unix_roots() {
        assert!(is_system_path(Path::new("/")));
        assert!(is_system_path(Path::new("/etc")));
        assert!(is_system_path(Path::new("/etc/frostwall")));
        assert!(is_system_path(Path::new("/private/etc")));
        assert!(is_system_path(Path::new("/Applications")));
        assert!(is_system_path(Path::new("/opt/homebrew")));
        assert!(!is_system_path(Path::new("/Users")));
    }

    #[test]
    fn is_windows_system_path_first_dir() {
        assert!(is_windows_system_path(Path::new("/Windows")));
        assert!(is_windows_system_path(Path::new("/Program Files/Foo")));
        assert!(is_windows_system_path(Path::new("/Program Files (x86)")));
        assert!(is_windows_system_path(Path::new("/ProgramData")));
        assert!(is_windows_system_path(Path::new("/")));
        assert!(!is_windows_system_path(Path::new("/Users")));
        assert!(!is_windows_system_path(Path::new("/Frostwall")));
    }

    #[cfg(windows)]
    #[test]
    fn is_system_path_rejects_windows_roots_on_any_drive() {
        assert!(is_system_path(Path::new(r"C:\Windows")));
        assert!(is_system_path(Path::new(r"D:\Windows\System32")));
        assert!(is_system_path(Path::new(r"\\?\C:\Windows")));
        assert!(is_system_path(Path::new(r"C:\Program Files")));
        assert!(is_system_path(Path::new(r"C:\Program Files (x86)\Foo")));
        assert!(is_system_path(Path::new(r"C:\ProgramData")));
        assert!(is_system_path(Path::new(r"C:\")));
        assert!(!is_system_path(Path::new(r"C:\Users")));
        assert!(!is_system_path(Path::new(r"D:\Frostwall")));
        assert!(!is_system_path(Path::new(r"C:\Users\me\Downloads")));
    }

    #[test]
    fn check_download_dir_rejects_system() {
        assert!(check_download_dir(Path::new("/etc")).is_err());
        assert!(check_download_dir(Path::new("/Applications")).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn check_download_dir_rejects_symlink_parent() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real");
        std::fs::create_dir(&real).unwrap();
        let link = dir.path().join("link");
        symlink(&real, &link).unwrap();
        assert!(check_download_dir(&link.join("out")).is_err());
    }

    #[tokio::test]
    async fn clear_aborts_pairing_task() {
        let state = AppState::new();
        let handle = async_runtime::spawn(async {
            tokio::time::sleep(Duration::from_secs(60)).await;
        });
        *state.pairing_task.lock().await = Some(handle);
        state.clear().await;
        assert!(state.pairing_task.lock().await.is_none());
    }

    #[tokio::test]
    async fn clear_aborts_coordinator_task() {
        let state = AppState::new();
        let ran = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&ran);
        let handle = async_runtime::spawn(async move {
            tokio::time::sleep(Duration::from_secs(60)).await;
            flag.store(true, Ordering::SeqCst);
        });
        *state.coordinator_task.lock().await = Some(handle);
        state.clear().await;
        assert!(state.coordinator_task.lock().await.is_none());
        tokio::time::sleep(Duration::from_millis(40)).await;
        assert!(
            !ran.load(Ordering::SeqCst),
            "disconnect must abort a hung coordinator, not wait out the send"
        );
    }

    #[tokio::test]
    async fn clear_drops_stale_peer_display_name() {
        let state = AppState::new();
        *state.peer_display_name.lock().await = Some("old-host".into());
        state.clear().await;
        assert!(state.peer_display_name.lock().await.is_none());
    }

    #[tokio::test]
    async fn clear_bumps_session_epoch() {
        let state = AppState::new();
        let a = state.epoch();
        state.clear().await;
        let b = state.epoch();
        assert_ne!(a, b);
        assert!(epoch_or_cancel(&state, a).is_err());
        assert!(epoch_or_cancel(&state, b).is_ok());
    }

    #[tokio::test]
    async fn stale_epoch_does_not_clear_newer_session() {
        let state = AppState::new();
        let old = state.epoch();
        state.clear().await;
        let newer = state.epoch();
        let handle = async_runtime::spawn(async {
            tokio::time::sleep(Duration::from_secs(60)).await;
        });
        *state.pairing_task.lock().await = Some(handle);
        if state.epoch() == old {
            state.clear().await;
        }
        assert_eq!(state.epoch(), newer);
        assert!(
            state.pairing_task.lock().await.is_some(),
            "dying coordinator must not abort a newer pairing task"
        );
        state.abort_pairing().await;
    }

    #[tokio::test]
    async fn stale_epoch_does_not_steal_newer_coordinator() {
        let state = AppState::new();
        let old = state.epoch();
        state.clear().await;
        let newer = state.epoch();
        let handle = async_runtime::spawn(async {
            tokio::time::sleep(Duration::from_secs(60)).await;
        });
        *state.coordinator_task.lock().await = Some(handle);
        {
            let mut slot = state.coordinator_task.lock().await;
            if state.epoch() == old {
                let _ = slot.take();
            }
        }
        assert_eq!(state.epoch(), newer);
        assert!(
            state.coordinator_task.lock().await.is_some(),
            "dying coordinator must not steal a newer session's abort handle"
        );
        state.abort_coordinator().await;
    }

    #[test]
    fn install_cancel_reuses_flag_so_early_cancel_survives() {
        let state = AppState::new();
        let a = install_cancel(&state);
        a.store(true, Ordering::SeqCst);
        let b = install_cancel(&state);
        assert!(Arc::ptr_eq(&a, &b));
        assert!(b.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn stale_epoch_does_not_clear_newer_transfer_flags() {
        let state = AppState::new();
        let old = state.epoch();
        try_reserve_transfer(&state).unwrap();
        let _old_flag = install_cancel(&state);
        state.clear().await;
        try_reserve_transfer(&state).unwrap();
        let new_flag = install_cancel(&state);
        if state.epoch() == old {
            if let Ok(mut g) = state.in_flight.lock() {
                *g = false;
            }
            clear_cancel(&state);
        }
        assert!(
            *state.in_flight.lock().unwrap(),
            "dying coordinator must not drop a newer in_flight gate"
        );
        assert!(
            state.active_cancel.lock().unwrap().is_some(),
            "dying coordinator must not drop a newer cancel flag"
        );
        assert!(!new_flag.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn wait_incoming_decision_skips_slot_when_epoch_stale() {
        let state = AppState::new();
        let old = state.epoch();
        state.clear().await;
        let (tx, _rx) = oneshot::channel::<bool>();
        *state.incoming_decision.lock().await = Some(tx);
        let pick = wait_incoming_decision(&state, old).await;
        assert!(matches!(pick, IncomingPick::Decline));
        assert!(
            state.incoming_decision.lock().await.is_some(),
            "stale wait must not steal a newer incoming-decision slot"
        );
    }

    async fn loopback_pair() -> (Connection, Connection) {
        let listener = transport::bind(0).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { transport::accept(&listener).await.unwrap() });
        let client = transport::connect(addr).await.unwrap();
        (client, server.await.unwrap())
    }

    #[tokio::test]
    async fn wait_incoming_sees_peer_cancel() {
        let state = AppState::new();
        let epoch = state.epoch();
        let keys = SessionKeys::derive(b"pending-cancel");
        let (mut a, mut b) = loopback_pair().await;
        let frame = transfer::seal_control(&keys, &Message::Cancel).unwrap();
        let (pick, _) = tokio::join!(
            wait_incoming_with_peer(&state, epoch, &mut b, &keys),
            async {
                a.send(&frame).await.unwrap();
            }
        );
        assert!(matches!(pick, IncomingPick::Cancelled), "{pick:?}");
        assert!(state.incoming_decision.lock().await.is_none());
    }

    #[tokio::test]
    async fn wait_incoming_sees_peer_drop() {
        let state = AppState::new();
        let epoch = state.epoch();
        let keys = SessionKeys::derive(b"pending-drop");
        let (a, mut b) = loopback_pair().await;
        let pick = tokio::time::timeout(Duration::from_secs(2), async {
            let close = async {
                tokio::time::sleep(Duration::from_millis(20)).await;
                drop(a);
            };
            let wait = wait_incoming_with_peer(&state, epoch, &mut b, &keys);
            tokio::join!(wait, close).0
        })
        .await
        .expect("peer drop should unblock the accept wait");
        assert!(matches!(pick, IncomingPick::Dropped), "{pick:?}");
        assert!(state.incoming_decision.lock().await.is_none());
    }

    #[tokio::test]
    async fn wait_incoming_accept_still_wins() {
        let state = AppState::new();
        let epoch = state.epoch();
        let keys = SessionKeys::derive(b"pending-accept");
        let (_a, mut b) = loopback_pair().await;
        let pick = tokio::time::timeout(Duration::from_secs(2), async {
            let accept = async {
                tokio::time::sleep(Duration::from_millis(20)).await;
                if let Some(tx) = state.incoming_decision.lock().await.take() {
                    tx.send(true).unwrap();
                }
            };
            let wait = wait_incoming_with_peer(&state, epoch, &mut b, &keys);
            tokio::join!(wait, accept).0
        })
        .await
        .expect("user accept should unblock");
        assert!(matches!(pick, IncomingPick::Accept), "{pick:?}");
    }

    #[test]
    fn interpret_peer_noise_classifies_control_frames() {
        let keys = SessionKeys::derive(b"noise");
        let hello = transfer::seal_control(&keys, &Message::Hello("x".into())).unwrap();
        assert_eq!(
            interpret_peer_during_idle(&keys, Ok(hello)),
            PeerNoise::Stray
        );
        let cancel = transfer::seal_control(&keys, &Message::Cancel).unwrap();
        assert_eq!(
            interpret_peer_during_idle(&keys, Ok(cancel)),
            PeerNoise::Cancel
        );
        let man = transfer::seal_control(
            &keys,
            &Message::Manifest(vec![crate::protocol::ManifestEntry {
                rel_path: "a.txt".into(),
                size: 1,
            }]),
        )
        .unwrap();
        assert_eq!(
            interpret_peer_during_idle(&keys, Ok(man)),
            PeerNoise::Manifest
        );
        assert_eq!(
            interpret_peer_during_idle(&keys, Err(anyhow::anyhow!("connection closed by peer"))),
            PeerNoise::Gone
        );
    }

    #[test]
    fn transfer_preview_caps_names_sent_to_ui() {
        let items: Vec<TransferItem> = (0..40)
            .map(|i| TransferItem {
                name: format!("f{i}"),
                size: 1,
            })
            .collect();
        let preview = transfer_preview(&items);
        assert_eq!(preview.len(), UI_ITEM_PREVIEW);
        assert_eq!(preview[0].name, "f0");
        assert_eq!(preview[UI_ITEM_PREVIEW - 1].name, format!("f{}", UI_ITEM_PREVIEW - 1));
    }
}
