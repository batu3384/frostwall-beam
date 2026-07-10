//! Tauri command layer: exposes host/join/send/liveness to the frontend and
//! runs a per-session coordinator task that owns the connection, racing local
//! send commands against incoming transfers (serialized, never concurrent).

use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync;
use std::sync::atomic::{AtomicBool, Ordering};
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
use crate::protocol::{self, Message};
use crate::session::{self, Session};
use crate::transfer;
use crate::transport::{self, Connection};

const EV_PROGRESS: &str = "frostwall://progress";
const EV_TRANSFER_START: &str = "frostwall://transfer-start";
const EV_TRANSFER_PENDING: &str = "frostwall://transfer-pending";
const EV_TRANSFER_DONE: &str = "frostwall://transfer-done";
const EV_PAIRED: &str = "frostwall://paired";
const EV_DISCONNECT: &str = "frostwall://disconnected";
const EV_ERROR: &str = "frostwall://error";

/// Max failed pairing handshakes before the host aborts (online brute-force
/// bound on the 6-digit code).
const MAX_PAIRING_ATTEMPTS: u32 = 5;

#[derive(Clone, Serialize)]
struct TransferItem {
    name: String,
    size: u64,
}

#[derive(Clone, Serialize)]
struct TransferStartPayload {
    direction: &'static str, // "sending" | "receiving"
    items: Vec<TransferItem>,
    total: u64,
    file_count: usize,
}

#[derive(Clone, Serialize)]
struct ProgressPayload {
    transferred: u64,
    total: u64,
    percent: f64,
    direction: &'static str,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct PairedPayload {
    peer_name: Option<String>,
    local_name: Option<String>,
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
    /// Set while the UI decides whether to accept an incoming transfer.
    incoming_decision: Mutex<Option<oneshot::Sender<bool>>>,
    /// Cancel flag for the transfer currently owned by the coordinator.
    active_cancel: sync::Mutex<Option<Arc<AtomicBool>>>,
    /// Display name of the peer we're connecting to (join side).
    peer_display_name: Mutex<Option<String>>,
    /// Active internet-host mailbox registration to unregister on disconnect/clear.
    internet_cleanup: Mutex<Option<InternetCleanup>>,
}

/// Mailbox registration held by an internet-mode host until pairing completes
/// or the session is torn down.
struct InternetCleanup {
    mailbox: internet::Mailbox,
    code: String,
    token: Option<String>,
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
            incoming_decision: Mutex::new(None),
            active_cancel: sync::Mutex::new(None),
            peer_display_name: Mutex::new(None),
            internet_cleanup: Mutex::new(None),
        }
    }

    async fn cleanup_internet(&self) {
        if let Some(c) = self.internet_cleanup.lock().await.take() {
            c.mailbox.unregister(&c.code, c.token.as_deref()).await;
        }
    }

    async fn abort_pairing(&self) {
        if let Some(h) = self.pairing_task.lock().await.take() {
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
        self.abort_pairing().await;
        self.trigger_cancel();
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

fn downloads_root() -> Option<PathBuf> {
    let base = dirs::download_dir().or_else(dirs::home_dir)?;
    Some(base.join("Frostwall Beam"))
}

/// Resolve the directory incoming files land in.
///
/// Honors the user-configured dir when set (the transfer layer creates it on
/// demand); otherwise uses the default `~/Downloads/Frostwall Beam`. If a
/// configured dir cannot be used, the transfer surfaces an explicit error
/// rather than silently redirecting files.
pub fn effective_download_dir(state: &AppState) -> PathBuf {
    let configured = state
        .download_dir
        .lock()
        .map(|g| g.clone())
        .unwrap_or(None);
    if let Some(cfg) = configured {
        return PathBuf::from(&cfg);
    }
    downloads_root().unwrap_or_else(|| PathBuf::from("."))
}

/// Reject obviously-dangerous system targets for the download dir.
fn is_system_path(p: &Path) -> bool {
    let c = std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
    if c == Path::new("/") {
        return true;
    }
    const UNIX_SYS: &[&str] = &[
        "/etc", "/usr", "/bin", "/sbin", "/var", "/tmp", "/private/var", "/private/tmp",
        "/dev", "/System", "/Library", "/boot", "/proc", "/sys",
    ];
    if UNIX_SYS.iter().any(|s| c.starts_with(s)) {
        return true;
    }
    #[cfg(windows)]
    {
        let upper = c.to_string_lossy().to_ascii_uppercase();
        const WIN_SYS: &[&str] = &[
            r"C:\WINDOWS",
            r"C:\PROGRAM FILES",
            r"C:\PROGRAM FILES (X86)",
            r"C:\PROGRAMDATA",
            r"C:\SYSTEM VOLUME INFORMATION",
        ];
        if WIN_SYS.iter().any(|prefix| upper.starts_with(prefix)) {
            return true;
        }
    }
    false
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

fn install_cancel(state: &AppState) -> Arc<AtomicBool> {
    let flag = Arc::new(AtomicBool::new(false));
    if let Ok(mut g) = state.active_cancel.lock() {
        *g = Some(flag.clone());
    }
    flag
}

fn clear_cancel(state: &AppState) {
    if let Ok(mut g) = state.active_cancel.lock() {
        *g = None;
    }
}

async fn wait_incoming_decision(state: &AppState) -> bool {
    let (tx, rx) = oneshot::channel();
    *state.incoming_decision.lock().await = Some(tx);
    rx.await.unwrap_or(false)
}

fn emit_progress(app: &AppHandle, p: transfer::Progress, direction: &'static str) {
    let percent = if p.total == 0 {
        100.0
    } else {
        p.transferred as f64 * 100.0 / p.total as f64
    };
    let _ = app.emit(
        EV_PROGRESS,
        ProgressPayload {
            transferred: p.transferred,
            total: p.total,
            percent,
            direction,
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
) {
    // Resolve the download dir up front from app state. `effective_download_dir`
    // clones the configured path out of its (std) lock and returns a PathBuf, so
    // no lock is held across any subsequent `.await`.
    let dest = match app.try_state::<AppState>() {
        Some(st) => effective_download_dir(&st),
        None => match downloads_root() {
            Some(d) => d,
            None => {
                let _ = app.emit(EV_ERROR, "no download directory available");
                return;
            }
        },
    };

    loop {
        tokio::select! {
            biased;
            cmd = cmd_rx.recv() => match cmd {
                Some(SessionCmd::Send { paths, reply }) => {
                    set_in_flight(&app, true);
                    let cancel = if let Some(st) = app.try_state::<AppState>() {
                        install_cancel(&st)
                    } else {
                        Arc::new(AtomicBool::new(false))
                    };
                    let result = match transfer::collect_items(&paths) {
                        Ok(items) => {
                            let tr_items: Vec<TransferItem> = items
                                .iter()
                                .map(|i| TransferItem {
                                    name: i.rel_path.clone(),
                                    size: std::fs::metadata(&i.source)
                                        .map(|m| m.len())
                                        .unwrap_or(0),
                                })
                                .collect();
                            let total: u64 = tr_items.iter().map(|i| i.size).sum();
                            let app = app.clone();
                            let _ = app.emit(
                                EV_TRANSFER_START,
                                TransferStartPayload {
                                    direction: "sending",
                                    items: tr_items.clone(),
                                    total,
                                    file_count: items.len(),
                                },
                            );
                            transfer::send(&mut conn, &keys, &items, &mut |p| {
                                emit_progress(&app, p, "sending")
                            }, &cancel)
                            .await
                        }
                        Err(e) => Err(e),
                    };
                    if let Some(st) = app.try_state::<AppState>() {
                        clear_cancel(&st);
                    }
                    let ok = result.is_ok();
                    set_in_flight(&app, false);
                    let _ = reply.send(result);
                    let _ = app.emit(EV_TRANSFER_DONE, ok);
                }
                None => break,
            },
            first = conn.recv() => match first {
                Ok(frame) => {
                    // Validate the manifest BEFORE showing it to the UI or
                    // writing anything (N3): reject unsafe paths/counts/sizes
                    // up front so a malicious transfer neither renders an
                    // attacker-chosen path nor reaches the file layer.
                    let entries = match protocol::decode(&frame) {
                        Ok(Message::Manifest(e)) => e,
                        Ok(other) => {
                            let _ = app.emit(EV_ERROR, format!("unexpected message: {other:?}"));
                            let _ = app.emit(EV_TRANSFER_DONE, false);
                            break;
                        }
                        Err(e) => {
                            let _ = app.emit(EV_ERROR, e.to_string());
                            let _ = app.emit(EV_TRANSFER_DONE, false);
                            break;
                        }
                    };
                    if let Err(e) = transfer::validate_manifest(&entries) {
                        let _ = app.emit(EV_ERROR, e.to_string());
                        let _ = app.emit(EV_TRANSFER_DONE, false);
                        break;
                    }
                    let items: Vec<TransferItem> = entries
                        .iter()
                        .map(|e| TransferItem { name: e.rel_path.clone(), size: e.size })
                        .collect();
                    let total: u64 = items.iter().map(|i| i.size).sum();
                    let count = items.len();
                    let _ = app.emit(
                        EV_TRANSFER_PENDING,
                        TransferStartPayload {
                            direction: "receiving",
                            items: items.clone(),
                            total,
                            file_count: count,
                        },
                    );
                    let accepted = if let Some(st) = app.try_state::<AppState>() {
                        wait_incoming_decision(&st).await
                    } else {
                        false
                    };
                    if !accepted {
                        if let Ok(reject) = protocol::encode(&Message::Reject) {
                            let _ = conn.send(&reject).await;
                        }
                        let _ = app.emit(EV_TRANSFER_DONE, false);
                        continue;
                    }
                    match protocol::encode(&Message::Accept) {
                        Ok(accept) => {
                            if let Err(e) = conn.send(&accept).await {
                                let _ = app.emit(EV_ERROR, e.to_string());
                                let _ = app.emit(EV_TRANSFER_DONE, false);
                                break;
                            }
                        }
                        Err(e) => {
                            let _ = app.emit(EV_ERROR, e.to_string());
                            let _ = app.emit(EV_TRANSFER_DONE, false);
                            break;
                        }
                    }
                    set_in_flight(&app, true);
                    let cancel = if let Some(st) = app.try_state::<AppState>() {
                        install_cancel(&st)
                    } else {
                        Arc::new(AtomicBool::new(false))
                    };
                    let _ = app.emit(
                        EV_TRANSFER_START,
                        TransferStartPayload {
                            direction: "receiving",
                            items,
                            total,
                            file_count: count,
                        },
                    );
                    let app = app.clone();
                    let dest = dest.clone();
                    let result = transfer::recv_from_first(
                        &mut conn,
                        &keys,
                        &dest,
                        &mut |p| emit_progress(&app, p, "receiving"),
                        frame,
                        &cancel,
                    )
                    .await;
                    if let Some(st) = app.try_state::<AppState>() {
                        clear_cancel(&st);
                    }
                    set_in_flight(&app, false);
                    if let Err(e) = result {
                        let _ = app.emit(EV_ERROR, e.to_string());
                        let _ = app.emit(EV_TRANSFER_DONE, false);
                        break;
                    }
                    let _ = app.emit(EV_TRANSFER_DONE, true);
                    let _ = app.emit(
                        "frostwall://received",
                        dest.to_string_lossy().to_string(),
                    );
                }
                Err(_) => {
                    let _ = app.emit(EV_DISCONNECT, "peer closed the connection");
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
    if let Some(st) = app.try_state::<AppState>() {
        st.clear().await;
    }
}

/// Install a freshly-paired session: store its liveness key + command channel
/// in app state, emit the paired event, and launch the coordinator.
async fn establish_session(app: &AppHandle, session: Session) {
    let (conn, keys) = session.into_parts();
    let liveness = keys.liveness_key;
    let (tx, rx) = mpsc::channel::<SessionCmd>(8);
    let (peer_name, local_name) = {
        let st = app.state::<AppState>();
        let peer = st.peer_display_name.lock().await.take();
        let local = local_display_name(&st);
        *st.liveness_key.lock().await = Some(liveness);
        *st.cmd_tx.lock().await = Some(tx);
        *st.pairing_task.lock().await = None;
        (peer, local)
    };
    let _ = app.emit(
        EV_PAIRED,
        PairedPayload {
            peer_name,
            local_name,
        },
    );
    let app = app.clone();
    async_runtime::spawn(async move {
        run_coordinator(app, keys, conn, rx).await;
    });
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
pub async fn host_start(app: AppHandle, state: State<'_, AppState>, code: String) -> Result<(), String> {
    state.clear().await;

    let ip = discovery::local_lan_ipv4()
        .map(IpAddr::V4)
        .unwrap_or_else(|| "127.0.0.1".parse().unwrap());
    let listener = transport::bind_to(ip, 0).await.map_err(|e| e.to_string())?;
    let port = listener.local_addr().map_err(|e| e.to_string())?.port();

    let mut disc = Discovery::new().map_err(|e| e.to_string())?;
    let instance = mdns_instance_name(&state);
    disc.advertise(&instance, ip, port).map_err(|e| e.to_string())?;

    let app = app.clone();
    let handle = async_runtime::spawn(async move {
        // Accept in a loop so a stalled/failed handshake does not consume the
        // only slot; abort after too many wrong-code failures (online brute-force bound).
        let mut bad_code_attempts = 0u32;
        loop {
            let conn = match transport::accept(&listener).await {
                Ok(c) => c,
                Err(e) => {
                    let _ = app.emit(EV_ERROR, e.to_string());
                    break;
                }
            };
            match session::host_handshake(conn, &code).await {
                Ok(session) => {
                    drop(disc); // stop advertising once paired
                    establish_session(&app, session).await;
                    break;
                }
                Err(e) => {
                    let msg = e.to_string();
                    // Slowloris stalls must not exhaust the pairing budget.
                    if msg.contains("timed out") || msg.contains("peer stalled") {
                        continue;
                    }
                    bad_code_attempts += 1;
                    if bad_code_attempts >= MAX_PAIRING_ATTEMPTS {
                        let _ = app.emit(
                            EV_ERROR,
                            format!("too many failed pairing attempts ({e}); please regenerate the code"),
                        );
                        break;
                    }
                }
            }
        }
    });
    *state.pairing_task.lock().await = Some(handle);

    Ok(())
}

/// Host: same pairing flow as [`host_start`], but reachable across
/// different networks. Publishes our `iroh` `EndpointId` under `code` on
/// the configured mailbox service instead of advertising via mDNS, and
/// accepts the joiner over a NAT-traversing iroh connection (direct when
/// possible, relayed otherwise) instead of a LAN TCP socket. The SPAKE2
/// handshake and everything after it is identical to the LAN path.
#[tauri::command]
pub async fn host_start_internet(
    app: AppHandle,
    state: State<'_, AppState>,
    code: String,
) -> Result<(), String> {
    state.clear().await;

    let mailbox_url = state
        .mailbox_url
        .lock()
        .map(|g| g.clone())
        .unwrap_or(None)
        .ok_or_else(|| "mailbox server is not configured".to_string())?;

    let ep = internet::host_endpoint().await.map_err(|e| e.to_string())?;
    let mailbox = internet::Mailbox::new(mailbox_url);
    let host_name = local_display_name(&state);
    let token = mailbox
        .register(
            &code,
            &internet::endpoint_id_string(&ep),
            host_name.as_deref(),
        )
        .await
        .map_err(|e| e.to_string())?;

    *state.internet_cleanup.lock().await = Some(InternetCleanup {
        mailbox: mailbox.clone(),
        code: code.clone(),
        token: Some(token.clone()),
    });

    let app = app.clone();
    let reg_token = token;
    let handle = async_runtime::spawn(async move {
        // Mirrors host_start's accept loop (see MAX_PAIRING_ATTEMPTS doc
        // there): a stalled or wrong-code handshake doesn't consume the
        // mailbox registration, only repeated failures do.
        let mut bad_code_attempts = 0u32;
        loop {
            let conn = match internet::accept_one(&ep).await {
                Ok(c) => c,
                Err(e) => {
                    let _ = app.emit(EV_ERROR, e.to_string());
                    break;
                }
            };
            match session::host_handshake(conn, &code).await {
                Ok(session) => {
                    mailbox.unregister(&code, Some(&reg_token)).await;
                    if let Some(st) = app.try_state::<AppState>() {
                        st.internet_cleanup.lock().await.take();
                    }
                    establish_session(&app, session).await;
                    break;
                }
                Err(e) => {
                    let msg = e.to_string();
                    if msg.contains("timed out") || msg.contains("peer stalled") {
                        continue;
                    }
                    bad_code_attempts += 1;
                    if bad_code_attempts >= MAX_PAIRING_ATTEMPTS {
                        let _ = app.emit(
                            EV_ERROR,
                            format!("too many failed pairing attempts ({e}); please regenerate the code"),
                        );
                        break;
                    }
                }
            }
        }
        mailbox.unregister(&code, Some(&reg_token)).await;
        if let Some(st) = app.try_state::<AppState>() {
            st.internet_cleanup.lock().await.take();
        }
    });
    *state.pairing_task.lock().await = Some(handle);

    Ok(())
}

/// Discover Frostwall hosts on the LAN (for multi-host selection).
#[tauri::command]
pub async fn discover_peers() -> Result<Vec<DiscoveredPeer>, String> {
    discovery::browse_peers(Duration::from_secs(5))
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
) -> Result<(), String> {
    state.clear().await;
    *state.peer_display_name.lock().await = display_name;

    let ip: IpAddr = address
        .parse()
        .map_err(|_| format!("invalid address: {address}"))?;
    let addr = SocketAddr::new(ip, port);

    let app = app.clone();
    let handle = async_runtime::spawn(async move {
        let conn = match transport::connect(addr).await {
            Ok(c) => c,
            Err(e) => {
                let _ = app.emit(EV_ERROR, e.to_string());
                return;
            }
        };
        match session::joiner_handshake(conn, &code).await {
            Ok(session) => establish_session(&app, session).await,
            Err(e) => {
                let _ = app.emit(EV_ERROR, e.to_string());
            }
        }
    });
    *state.pairing_task.lock().await = Some(handle);

    Ok(())
}

/// Joiner: discover a host on the LAN, connect, run the SPAKE2 handshake.
#[tauri::command]
pub async fn join(app: AppHandle, state: State<'_, AppState>, code: String) -> Result<(), String> {
    let peers = discover_peers().await?;
    let peer = peers
        .into_iter()
        .next()
        .ok_or_else(|| "no peer found on the LAN".to_string())?;
    join_peer(
        app,
        state,
        code,
        peer.address,
        peer.port,
        Some(peer.display_name),
    )
    .await
}

/// Joiner: same pairing flow as [`join`], but for a host on a different
/// network. Looks the host's `EndpointId` up on the configured mailbox
/// service by `code`, then dials it over `iroh` (direct connection when
/// NAT allows, transparently relayed otherwise).
#[tauri::command]
pub async fn join_internet(app: AppHandle, state: State<'_, AppState>, code: String) -> Result<(), String> {
    state.clear().await;

    let mailbox_url = state
        .mailbox_url
        .lock()
        .map(|g| g.clone())
        .unwrap_or(None)
        .ok_or_else(|| "mailbox server is not configured".to_string())?;

    let app = app.clone();
    let handle = async_runtime::spawn(async move {
        let mailbox = internet::Mailbox::new(mailbox_url);
        let peer = match mailbox.lookup(&code).await {
            Ok(peer) => peer,
            Err(e) => {
                let _ = app.emit(EV_ERROR, e.to_string());
                return;
            }
        };
        if let Some(st) = app.try_state::<AppState>() {
            *st.peer_display_name.lock().await = peer.device_name;
        }
        let endpoint_id = peer.endpoint_id;
        let ep = match internet::join_endpoint().await {
            Ok(ep) => ep,
            Err(e) => {
                let _ = app.emit(EV_ERROR, e.to_string());
                return;
            }
        };
        let conn = match internet::connect_to(&ep, &endpoint_id).await {
            Ok(c) => c,
            Err(e) => {
                let _ = app.emit(EV_ERROR, e.to_string());
                return;
            }
        };
        match session::joiner_handshake(conn, &code).await {
            Ok(session) => establish_session(&app, session).await,
            Err(e) => {
                let _ = app.emit(EV_ERROR, e.to_string());
            }
        }
    });
    *state.pairing_task.lock().await = Some(handle);

    Ok(())
}

/// Send a list of files/folders to the peer.
#[tauri::command]
pub async fn send_files(state: State<'_, AppState>, paths: Vec<String>) -> Result<(), String> {
    // Reject if a transfer is already in flight so two sends can't pile up
    // and reuse the single progress bar confusingly.
    let in_flight = state
        .in_flight
        .lock()
        .map(|g| *g)
        .unwrap_or(false);
    if in_flight {
        return Err("a transfer is already in progress".to_string());
    }
    let tx = state
        .cmd_tx
        .lock()
        .await
        .clone()
        .ok_or_else(|| "not connected".to_string())?;
    let paths: Vec<PathBuf> = paths.into_iter().map(PathBuf::from).collect();
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(SessionCmd::Send {
        paths,
        reply: reply_tx,
    })
    .await
    .map_err(|_| "coordinator stopped".to_string())?;
    reply_rx
        .await
        .map_err(|_| "session ended (peer disconnected or transfer cancelled)".to_string())?
        .map_err(|e| e.to_string())
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
        .flatten();
    Ok(ConfigPayload {
        download_dir,
        device_name,
        mailbox_url,
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
    // Ensure the directory exists: accept if it already is a dir, or create it.
    if !p.is_dir() {
        std::fs::create_dir_all(&p)
            .map_err(|e| format!("could not access or create directory {path}: {e}"))?;
    }
    // Validation (defense-in-depth on top of the transfer-layer confinement).
    let meta = std::fs::symlink_metadata(&p)
        .map_err(|e| format!("could not read directory {path}: {e}"))?;
    if meta.is_symlink() {
        return Err("download directory must not be a symlink".to_string());
    }
    if !meta.is_dir() {
        return Err("path is not a directory".to_string());
    }
    if is_system_path(&p) {
        return Err("refusing a system directory as the download location".to_string());
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
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err("device name must not be empty".to_string());
    }
    let value = trimmed.to_string();
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

/// Set (or, if blank, clear) the mailbox rendezvous URL used for internet
/// sessions. A non-empty value must look like an `http(s)://` URL.
#[tauri::command]
pub async fn set_mailbox_url(state: State<'_, AppState>, url: String) -> Result<(), String> {
    let trimmed = url.trim();
    let value = if trimmed.is_empty() {
        None
    } else {
        if !(trimmed.starts_with("http://") || trimmed.starts_with("https://")) {
            return Err("mailbox URL must start with http:// or https://".to_string());
        }
        Some(trimmed.trim_end_matches('/').to_string())
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
    }

    #[tokio::test]
    async fn clear_aborts_pairing_task() {
        let state = AppState::new();
        let handle = tokio::spawn(async {
            tokio::time::sleep(Duration::from_secs(60)).await;
        });
        *state.pairing_task.lock().await = Some(handle);
        state.clear().await;
        assert!(state.pairing_task.lock().await.is_none());
    }
}
