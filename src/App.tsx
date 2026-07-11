import { useCallback, useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import { getCurrentWebview } from "@tauri-apps/api/webview";
import { open } from "@tauri-apps/plugin-dialog";
import brand from "./assets/brand.png";
import { translateError } from "./errors";
import { appendHistory, loadHistory, type TransferRecord } from "./history";
import { useI18n, type Lang } from "./i18n";
import { applyTheme, readTheme, saveTheme, watchSystemTheme, type Theme } from "./theme";

type Phase = "idle" | "hosting" | "joining" | "connected";
type Mode = "host" | "join";
type Net = "lan" | "internet";

interface TransferItem { name: string; size: number; }
interface TransferStart {
  direction: "sending" | "receiving";
  items: TransferItem[];
  total: number;
  file_count: number;
}
interface Progress {
  transferred: number; total: number; percent: number;
  direction: "sending" | "receiving";
}
interface Toast { id: number; kind: "ok" | "err" | "info"; msg: string; }
interface AppConfig { downloadDir: string | null; deviceName: string | null; mailboxUrl: string | null; }
interface DiscoveredPeer { displayName: string; address: string; port: number; }
interface PairedPayload { peerName: string | null; localName: string | null; }

const STEP = 30;

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  const u = ["KB", "MB", "GB", "TB"];
  let v = n / 1024, i = 0;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return `${v.toFixed(v >= 100 ? 0 : 1)} ${u[i]}`;
}
function basename(p: string): string {
  const parts = p.replace(/\\/g, "/").split("/");
  return parts[parts.length - 1] || p;
}

export default function App() {
  const { t, lang, setLang } = useI18n();

  const [phase, setPhase] = useState<Phase>("idle");
  const [mode, setMode] = useState<Mode>("host");
  const [net, setNet] = useState<Net>("lan");
  const [code, setCode] = useState("");
  const [joinCode, setJoinCode] = useState("");
  const [liveness, setLiveness] = useState("");
  const [secLeft, setSecLeft] = useState(STEP);
  const [copied, setCopied] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [transfer, setTransfer] = useState<TransferStart | null>(null);
  const [progress, setProgress] = useState<Progress | null>(null);
  const [transferDone, setTransferDone] = useState(false);
  const [speed, setSpeed] = useState(0);

  const [dragging, setDragging] = useState(false);
  const [toasts, setToasts] = useState<Toast[]>([]);

  const [config, setConfig] = useState<AppConfig | null>(null);
  const [showSettings, setShowSettings] = useState(false);
  const [pendingTransfer, setPendingTransfer] = useState<TransferStart | null>(null);
  const [peerChoices, setPeerChoices] = useState<DiscoveredPeer[] | null>(null);
  const [peerName, setPeerName] = useState<string | null>(null);
  const [localName, setLocalName] = useState<string | null>(null);
  const [history, setHistory] = useState<TransferRecord[]>(() => loadHistory());
  const [theme, setThemeState] = useState<Theme>(() => readTheme());

  const phaseRef = useRef(phase);
  phaseRef.current = phase;
  const transferRef = useRef(transfer);
  transferRef.current = transfer;
  const speedRef = useRef({ at: 0, bytes: 0, speed: 0 });
  const toastId = useRef(0);

  const pushToast = useCallback((kind: Toast["kind"], msg: string) => {
    const id = ++toastId.current;
    setToasts((s) => [...s, { id, kind, msg }].slice(-3));
    setTimeout(() => setToasts((s) => s.filter((x) => x.id !== id)), 4200);
  }, []);

  const showError = useCallback((raw: string) => {
    setError(translateError(raw, t));
  }, [t]);

  const refreshConfig = useCallback(async () => {
    try { setConfig(await invoke<AppConfig>("get_config")); } catch { /* ignore */ }
  }, []);

  const reset = useCallback((msgKey?: string) => {
    setPhase("idle"); setLiveness(""); setTransfer(null); setProgress(null);
    setTransferDone(false); setCode(""); setJoinCode(""); setPendingTransfer(null);
    setPeerChoices(null); setPeerName(null); setLocalName(null);
    speedRef.current = { at: 0, bytes: 0, speed: 0 };
    if (msgKey) pushToast("info", t(msgKey));
  }, [pushToast, t]);

  const setTheme = useCallback((next: Theme) => {
    setThemeState(next);
    saveTheme(next);
    applyTheme(next);
  }, []);

  useEffect(() => {
    if (theme !== "system") return;
    return watchSystemTheme(() => applyTheme("system"));
  }, [theme]);

  const respondPending = useCallback(async (accept: boolean) => {
    try {
      await invoke("respond_incoming_transfer", { accept });
      setPendingTransfer(null);
      if (!accept) pushToast("info", t("toast.transferRejected"));
    } catch (e) {
      showError(String(e));
    }
  }, [pushToast, showError, t]);

  useEffect(() => { refreshConfig(); }, [refreshConfig]);

  // global event listeners (StrictMode-safe)
  useEffect(() => {
    let cancelled = false;
    let unlistens: UnlistenFn[] = [];
    (async () => {
      const add = <T,>(name: string, h: (p: T) => void) =>
        listen<T>(name, (e) => !cancelled && h(e.payload as T));
      unlistens.push(await add<PairedPayload>("frostwall://paired", (p) => {
        setPhase("connected"); setTransfer(null); setProgress(null); setTransferDone(false);
        setPeerName(p.peerName); setLocalName(p.localName);
        pushToast("ok", t("toast.connected"));
      }));
      unlistens.push(await add<TransferStart>("frostwall://transfer-pending", (tr) => {
        setPendingTransfer(tr);
      }));
      unlistens.push(await add<Progress>("frostwall://progress", (p) => {
        const now = performance.now();
        const r = speedRef.current;
        const dt = (now - r.at) / 1000;
        if (r.at > 0 && dt > 0) {
          const inst = (p.transferred - r.bytes) / dt;
          r.speed = r.speed * 0.7 + inst * 0.3;
        }
        r.at = now; r.bytes = p.transferred; setSpeed(r.speed); setProgress(p);
      }));
      unlistens.push(await add<TransferStart>("frostwall://transfer-start", (tr) => {
        speedRef.current = { at: 0, bytes: 0, speed: 0 };
        setSpeed(0);
        setTransfer(tr); setTransferDone(false);
        setProgress({ transferred: 0, total: tr.total, percent: 0, direction: tr.direction });
      }));
      unlistens.push(await add<boolean>("frostwall://transfer-done", (ok) => {
        const tr = transferRef.current;
        if (tr) {
          setHistory(appendHistory({
            direction: tr.direction,
            fileCount: tr.file_count,
            totalBytes: tr.total,
            ok,
          }));
        }
        if (!ok) {
          pushToast("err", t("toast.transferFailed"));
          setTransfer(null); setProgress(null); setSpeed(0);
          return;
        }
        setTransferDone(true);
        setTimeout(() => { setTransfer(null); setProgress(null); setTransferDone(false); }, 1600);
      }));
      unlistens.push(await add<string>("frostwall://received", (dest) => {
        pushToast("ok", t("toast.savedTo").replace("{x}", basename(dest)));
      }));
      unlistens.push(await add("frostwall://disconnected", () => reset("toast.disconnected")));
      unlistens.push(await add<string>("frostwall://error", (e) => {
        showError(e); reset();
      }));
    })();
    return () => { cancelled = true; unlistens.forEach((u) => u()); };
  }, [pushToast, reset, showError, t]);

  useEffect(() => {
    if (phase !== "connected") return;
    let active = true;
    const tick = async () => {
      try {
        const c = await invoke<string | null>("current_liveness_code");
        if (active && c) { setLiveness(c); setSecLeft(STEP - (Math.floor(Date.now() / 1000) % STEP)); }
      } catch { /* ignore */ }
    };
    tick();
    const id = setInterval(tick, 1000);
    return () => { active = false; clearInterval(id); };
  }, [phase]);

  const send = useCallback(async (paths: string[]) => {
    if (paths.length === 0) return;
    setError(null);
    try { await invoke("send_files", { paths }); }
    catch (e) { showError(String(e)); }
  }, [showError]);

  useEffect(() => {
    const w = getCurrentWebview();
    const un = w.onDragDropEvent(async (e) => {
      if (e.payload.type === "enter" || e.payload.type === "over") {
        if (phaseRef.current === "connected") setDragging(true);
      } else if (e.payload.type === "leave") setDragging(false);
      else if (e.payload.type === "drop") {
        setDragging(false);
        if (phaseRef.current === "connected") await send(e.payload.paths);
      }
    });
    return () => { un.then((u) => u()); };
  }, [send]);

  const startHost = useCallback(async () => {
    setError(null);
    if (net === "internet" && !config?.mailboxUrl?.trim()) {
      showError(t("err.mailboxNotConfigured"));
      return;
    }
    try {
      const c = await invoke<string>("generate_code");
      setCode(c); setPhase("hosting");
      await invoke(net === "internet" ? "host_start_internet" : "host_start", { code: c });
    } catch (e) { showError(String(e)); setPhase("idle"); }
  }, [net, showError, config?.mailboxUrl]);

  const startJoin = useCallback(async () => {
    if (joinCode.length !== 6) { showError(t("join.error6")); return; }
    if (net === "internet" && !config?.mailboxUrl?.trim()) {
      showError(t("err.mailboxNotConfigured"));
      return;
    }
    setError(null); setPhase("joining"); setPeerChoices(null);
    try {
      if (net === "internet") {
        await invoke("join_internet", { code: joinCode });
        return;
      }
      const peers = await invoke<DiscoveredPeer[]>("discover_peers");
      if (peers.length === 0) {
        showError(t("err.noPeer"));
        setPhase("idle");
        return;
      }
      if (peers.length === 1) {
        await invoke("join_peer", {
          code: joinCode,
          address: peers[0].address,
          port: peers[0].port,
          displayName: peers[0].displayName,
        });
        return;
      }
      setPeerChoices(peers);
    } catch (e) { showError(String(e)); setPhase("idle"); }
  }, [joinCode, net, showError, t, config?.mailboxUrl]);

  const connectToPeer = useCallback(async (peer: DiscoveredPeer) => {
    setPeerChoices(null);
    setPhase("joining");
    try {
      await invoke("join_peer", {
        code: joinCode,
        address: peer.address,
        port: peer.port,
        displayName: peer.displayName,
      });
    } catch (e) {
      showError(String(e));
      setPhase("idle");
    }
  }, [joinCode, showError]);

  const cancelTransfer = useCallback(async () => {
    try {
      await invoke("cancel_transfer");
      pushToast("info", t("toast.transferCancelled"));
    } catch (e) { showError(String(e)); }
  }, [pushToast, showError, t]);

  const pickFiles = useCallback(async () => {
    const r = await open({ multiple: true });
    if (!r) return;
    await send(Array.isArray(r) ? r.map(String) : [String(r)]);
  }, [send]);

  const pickFolder = useCallback(async () => {
    const r = await open({ directory: true });
    if (!r) return;
    await send([String(r)]);
  }, [send]);

  const doDisconnect = useCallback(async () => {
    await invoke("disconnect").catch(() => {}); reset();
  }, [reset]);

  const copyCode = useCallback(() => {
    navigator.clipboard?.writeText(code).then(() => {
      setCopied(true); setTimeout(() => setCopied(false), 1500);
    });
  }, [code]);

  const chooseSaveDir = useCallback(async () => {
    const r = await open({ directory: true });
    if (!r) return;
    try {
      await invoke("set_download_dir", { path: String(r) });
      await refreshConfig();
      pushToast("ok", t("settings.saveDir"));
    } catch (e) { showError(String(e)); }
  }, [refreshConfig, pushToast, showError, t]);

  const saveDirLabel = config?.downloadDir ?? t("settings.saveDirDefault");

  const mailboxReady = Boolean(config?.mailboxUrl?.trim());
  const internetBlocked = net === "internet" && !mailboxReady;
  const busy = phase === "hosting" || phase === "joining";
  const eta = progress && speed > 0 ? Math.ceil((progress.total - progress.transferred) / speed) : 0;
  const pct = progress ? progress.percent : 0;

  return (
    <div className="relative h-full w-full overflow-hidden text-[var(--text-body)]">
      <div className="pointer-events-none absolute inset-0 app-shell" />

      <div className="relative flex h-full flex-col">
        {/* Header — constrained inner band for balance */}
        <header className="px-5 py-3">
          <div className="mx-auto flex w-full max-w-[720px] items-center justify-between">
            <img src={brand} alt="Frostwall Beam"
              className="h-8 max-h-8 w-auto max-w-[180px] min-w-0 shrink object-contain self-center select-none"
              draggable={false}
              style={{ filter: "drop-shadow(0 2px 8px rgba(56,189,248,0.22))" }} />
            <div className="flex shrink-0 items-center gap-2">
              <button onClick={() => setShowSettings(true)} title={t("settings.title")} aria-label={t("settings.title")}
                className="frost-panel flex h-8 w-8 items-center justify-center rounded-full text-slate-300 transition hover:text-sky-200">
                <Icon name="gear" />
              </button>
              <StatusPill phase={phase} t={t} />
            </div>
          </div>
        </header>

        {/* Main — centers when short, scrolls when tall (no top clipping) */}
        <main className="flex-1 overflow-y-auto px-6 pb-6">
          <div className="mx-auto flex min-h-full w-full max-w-[560px] items-center justify-center py-4">
            <div className="w-full">
              {error && (
                <div role="alert" aria-live="assertive"
                  className="animate-fade-in mb-4 flex items-start gap-2 rounded-xl border border-rose-400/25 bg-rose-500/10 px-4 py-3 text-sm text-rose-200">
                  <Icon name="alert" className="mt-0.5 shrink-0 text-rose-300" />
                  <span className="min-w-0 flex-1">{error}</span>
                  <button type="button" onClick={() => setError(null)} aria-label={t("common.dismiss")}
                    className="shrink-0 rounded-lg p-1 text-rose-300/80 transition hover:bg-rose-500/20 hover:text-rose-100">
                    <Icon name="close" />
                  </button>
                </div>
              )}

              {/* IDLE */}
              {phase === "idle" && (
                <div className="animate-fade-in space-y-6">
                  <div className="text-center">
                    <h1 className="text-4xl font-semibold tracking-tight text-ice-gradient">{t("hero.title")}</h1>
                    <p className="mt-2 text-sm text-muted">{t("hero.subtitle")}</p>
                  </div>

                  <div className="frost-panel flex rounded-2xl p-1">
                    {(["host", "join"] as Mode[]).map((m) => (
                      <button key={m} type="button" onClick={() => setMode(m)} aria-pressed={mode === m}
                        className={`flex-1 rounded-xl px-4 py-2.5 text-sm font-medium transition ${
                          mode === m
                            ? "bg-gradient-to-r from-sky-500/90 to-cyan-500/90 text-white shadow-lg shadow-sky-500/20"
                            : "text-slate-400 hover:bg-white/5 hover:text-slate-200 active:scale-[0.97]"}`}>
                        {t(`mode.${m}`)}
                      </button>
                    ))}
                  </div>

                  <div className="flex justify-center gap-1 text-xs">
                    {(["lan", "internet"] as Net[]).map((n) => (
                      <button key={n} type="button" onClick={() => setNet(n)} aria-pressed={net === n}
                        className={`rounded-full px-3 py-1 font-medium transition ${
                          net === n
                            ? "bg-sky-400/15 text-sky-200"
                            : "text-slate-500 hover:text-slate-300"}`}>
                        {t(`net.${n}`)}
                      </button>
                    ))}
                  </div>

                  {mode === "host" ? (
                    <div className="frost-panel rounded-2xl p-6">
                      <p className="mb-2 text-sm font-medium text-sky-50">{t("host.heading")}</p>
                      <p className="mb-5 text-sm text-muted">{t(net === "internet" ? "host.descInternet" : "host.desc")}</p>
                      {internetBlocked && (
                        <p className="mb-4 text-sm text-amber-300/90">{t("net.mailboxRequired")}</p>
                      )}
                      <button onClick={startHost} disabled={internetBlocked}
                        className="frost-glow w-full rounded-xl bg-gradient-to-r from-sky-400 via-sky-500 to-cyan-500 px-4 py-3.5 font-medium text-white transition enabled:hover:brightness-110 active:scale-[0.99] disabled:opacity-40">
                        {t("host.button")}
                      </button>
                    </div>
                  ) : (
                    <div className="frost-panel rounded-2xl p-6">
                      <p className="mb-2 text-sm font-medium text-sky-50">{t("join.heading")}</p>
                      <p className="mb-5 text-sm text-muted">{t(net === "internet" ? "join.descInternet" : "join.desc")}</p>
                      {internetBlocked && (
                        <p className="mb-4 text-sm text-amber-300/90">{t("net.mailboxRequired")}</p>
                      )}
                      <div className="flex gap-2">
                        <input id="join-code" value={joinCode} aria-label={t("join.heading")}
                          onChange={(e) => setJoinCode(e.target.value.replace(/\D/g, "").slice(0, 6))}
                          onKeyDown={(e) => e.key === "Enter" && startJoin()}
                          inputMode="numeric" placeholder="••••••"
                          className="font-mono-num min-w-0 flex-1 rounded-xl border border-sky-300/15 bg-slate-950/50 px-4 py-3.5 text-center text-2xl tracking-[0.45em] text-sky-50 outline-none transition focus-visible:border-sky-400/60" />
                        <button onClick={startJoin} disabled={joinCode.length !== 6 || internetBlocked}
                          className="frost-glow shrink-0 rounded-xl bg-gradient-to-r from-sky-400 via-sky-500 to-cyan-500 px-6 py-3.5 font-medium text-white transition enabled:hover:brightness-110 active:scale-[0.99] disabled:opacity-40">
                          {t("join.button")}
                        </button>
                      </div>
                    </div>
                  )}
                  <Footer t={t} />
                </div>
              )}

              {/* WAITING */}
              {busy && (
                <div className="animate-fade-in frost-panel relative overflow-hidden rounded-2xl p-8">
                  {phase === "hosting" ? (
                    <div className="flex flex-col items-center gap-1.5 text-center">
                      <p className="text-xs font-medium uppercase tracking-[0.25em] text-sky-300/80">{t("waiting.codeLabel")}</p>
                      <button onClick={copyCode} title={t("waiting.copyHint")}
                        className="font-mono-num group relative mt-3 rounded-2xl text-6xl font-semibold tracking-[0.3em] text-sky-50 transition hover:scale-[1.02] active:scale-[0.98]">
                        {code}
                        <span className="absolute -inset-4 -z-10 rounded-3xl bg-sky-400/10 blur-2xl transition group-hover:bg-sky-400/20" />
                      </button>
                      <div className="mt-2 text-xs text-slate-400">
                        {copied ? <span className="text-sky-300">{t("waiting.copied")}</span> : t("waiting.copyHint")}
                      </div>
                      <p className="mt-6 text-sm text-muted">{t("waiting.hostWait")}</p>
                    </div>
                  ) : (
                    <div className="flex flex-col items-center gap-5 text-center">
                      <div className="relative flex h-16 w-16 items-center justify-center">
                        <span className="absolute inline-flex h-12 w-12 rounded-full bg-sky-400/20 animate-radar" />
                        <span className="absolute inline-flex h-12 w-12 rounded-full bg-cyan-400/10 animate-radar [animation-delay:0.8s]" />
                        <span className="relative h-10 w-10 rounded-full bg-gradient-to-br from-sky-400 to-cyan-500" />
                      </div>
                      <p className="text-sm text-muted">
                        {t(net === "internet" ? "join.waitingInternet" : "joining.scanning")}
                      </p>
                    </div>
                  )}
                  <div className="mt-7 flex justify-center">
                    <button onClick={() => { void doDisconnect(); }}
                      className="rounded-lg px-3 py-1.5 text-sm text-slate-400 transition hover:bg-white/5 hover:text-slate-200 active:scale-[0.98]">
                      {t("common.cancel")}
                    </button>
                  </div>
                </div>
              )}

              {/* CONNECTED */}
              {phase === "connected" && (
                <div className="animate-fade-in space-y-5">
                  <div className="frost-panel rounded-2xl p-6">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2 text-xs font-medium uppercase tracking-[0.2em] text-emerald-300/90">
                        <span className="relative flex h-2 w-2">
                          <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400 opacity-70" />
                          <span className="relative inline-flex h-2 w-2 rounded-full bg-emerald-400" />
                        </span>
                        {t("connected.secure")}
                      </div>
                      <span className="text-xs text-slate-400">{t("connected.rotates").replace("{n}", String(secLeft))}</span>
                    </div>
                    <div className="mt-4 min-w-0 break-all font-mono-num text-4xl font-semibold tracking-[0.35em] text-sky-50">{liveness}</div>
                    <div className="mt-4 h-1 w-full overflow-hidden rounded-full bg-white/5">
                      <div className="h-full rounded-full bg-gradient-to-r from-sky-400 to-cyan-400 transition-[width] duration-1000 ease-linear"
                        style={{ width: `${(secLeft / STEP) * 100}%` }} />
                    </div>
                    <p className="mt-3 text-xs text-slate-400">{t("connected.codeHint")}</p>
                    {(peerName || localName) && (
                      <div className="mt-4 space-y-1 border-t border-sky-300/10 pt-3 text-xs text-slate-400">
                        {localName && <p>{t("connected.you").replace("{name}", localName)}</p>}
                        <p>{peerName
                          ? t("connected.peer").replace("{name}", peerName)
                          : t("connected.peerGeneric")}</p>
                      </div>
                    )}
                  </div>

                  {transfer ? (
                    <TransferCard transfer={transfer} progress={progress} pct={pct} speed={speed} eta={eta}
                      done={transferDone} t={t} onCancel={cancelTransfer} />
                  ) : (
                    <div role="region" aria-label={t("drop.hint")}
                      className={`relative flex flex-col items-center justify-center rounded-2xl border-2 border-dashed p-10 text-center transition ${
                        dragging ? "border-sky-400/70 bg-sky-400/10" : "border-sky-300/25 bg-white/[0.05]"}`}>
                      <div className="mb-3 flex h-12 w-12 items-center justify-center rounded-xl bg-sky-400/10">
                        <Icon name="upload" className="text-sky-300" />
                      </div>
                      <p className="text-sm text-slate-200">{t("drop.hint")}</p>
                      <p className="mb-4 mt-0.5 text-xs text-slate-500">{t("drop.or")}</p>
                      <div className="flex gap-2">
                        <button onClick={pickFiles}
                          className="frost-glow rounded-xl bg-gradient-to-r from-sky-400 via-sky-500 to-cyan-500 px-4 py-2.5 text-sm font-medium text-white transition hover:brightness-110 active:scale-[0.98]">
                          {t("drop.files")}
                        </button>
                        <button onClick={pickFolder}
                          className="rounded-xl border border-sky-300/15 bg-white/[0.06] px-4 py-2.5 text-sm font-medium text-sky-100 transition hover:bg-white/[0.10] active:scale-[0.98]">
                          {t("drop.folder")}
                        </button>
                      </div>
                      <p className="mt-5 max-w-full truncate text-xs text-slate-400" title={saveDirLabel}>↧ {saveDirLabel}</p>
                    </div>
                  )}

                  <button onClick={doDisconnect}
                    className="w-full rounded-xl border border-sky-300/15 bg-white/[0.04] px-4 py-3 text-sm font-medium text-slate-300 transition hover:bg-white/[0.08] hover:text-rose-200 active:scale-[0.99]">
                    {t("btn.disconnect")}
                  </button>
                </div>
              )}
            </div>
          </div>
        </main>
      </div>

      {peerChoices && peerChoices.length > 1 && (
        <PeerPickerModal peers={peerChoices} t={t}
          onPick={connectToPeer} onCancel={() => { void doDisconnect(); }} />
      )}

      {pendingTransfer && (
        <PendingTransferModal transfer={pendingTransfer} t={t} formatBytes={formatBytes}
          onAccept={() => respondPending(true)} onReject={() => respondPending(false)} />
      )}

      {showSettings && (
        <SettingsModal t={t} lang={lang} setLang={setLang} theme={theme} setTheme={setTheme}
          config={config} saveDirLabel={saveDirLabel} history={history}
          formatBytes={formatBytes}
          onChooseSaveDir={chooseSaveDir} onClose={() => setShowSettings(false)}
          onError={showError} onSaved={refreshConfig} />
      )}

      {/* toasts */}
      <div aria-live="polite" className="pointer-events-none absolute bottom-5 left-1/2 z-50 flex max-h-[50vh] -translate-x-1/2 flex-col items-center gap-2 overflow-y-auto">
        {toasts.map((to) => (
          <div key={to.id}
            className={`animate-fade-in pointer-events-auto flex items-center gap-2 rounded-xl border px-4 py-2.5 text-sm shadow-2xl backdrop-blur-md ${
              to.kind === "ok" ? "border-emerald-400/25 bg-emerald-500/15 text-emerald-100"
              : to.kind === "err" ? "border-rose-400/25 bg-rose-500/15 text-rose-100"
              : "border-sky-300/20 bg-sky-500/15 text-sky-100"}`}>
            <Icon name={to.kind === "ok" ? "check" : to.kind === "err" ? "alert" : "info"} className="shrink-0 opacity-90" />
            {to.msg}
          </div>
        ))}
      </div>
    </div>
  );
}

/* ---------- sub-components ---------- */

function StatusPill({ phase, t }: { phase: Phase; t: (k: string) => string }) {
  const map: Record<Phase, { key: string; dot: string; text: string }> = {
    idle: { key: "status.offline", dot: "bg-slate-500", text: "text-slate-400" },
    hosting: { key: "status.hosting", dot: "bg-amber-400", text: "text-amber-200" },
    joining: { key: "status.connecting", dot: "bg-amber-400", text: "text-amber-200" },
    connected: { key: "status.encrypted", dot: "bg-emerald-400", text: "text-emerald-200" },
  };
  const s = map[phase];
  return (
    <div className="frost-panel flex h-8 items-center gap-2 rounded-full px-3 text-xs font-medium">
      <span className={`h-1.5 w-1.5 rounded-full ${s.dot}`} />
      <span className={s.text}>{t(s.key)}</span>
    </div>
  );
}

function TransferCard({ transfer, progress, pct, speed, eta, done, t, onCancel }: {
  transfer: TransferStart; progress: Progress | null; pct: number; speed: number; eta: number; done: boolean;
  t: (k: string) => string; onCancel: () => void;
}) {
  const sending = transfer.direction === "sending";
  const transferred = progress?.transferred ?? 0;
  const fileWord = transfer.file_count === 1 ? t("transfer.fileOne") : t("transfer.fileMany");
  return (
    <div className="frost-panel rounded-2xl p-6">
      <div className="mb-3 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <span className={`flex h-7 w-7 items-center justify-center rounded-lg ${sending ? "bg-sky-400/15 text-sky-300" : "bg-cyan-400/15 text-cyan-300"}`}>
            <Icon name={sending ? "upload" : "download"} />
          </span>
          <span className="text-sm font-medium text-sky-50">{done ? t("transfer.completed") : t(`transfer.${transfer.direction === "sending" ? "sending" : "receiving"}`)}</span>
          <span className="text-xs text-slate-400">· {transfer.file_count} {fileWord}</span>
        </div>
        <span className="font-mono-num text-sm text-slate-300">{pct.toFixed(0)}%</span>
      </div>

      <div className="mb-4 max-h-32 space-y-1 overflow-auto pr-1">
        {transfer.items.map((it, i) => (
          <div key={i} className="flex items-center justify-between rounded-lg bg-white/[0.02] px-3 py-1.5">
            <div className="flex min-w-0 items-center gap-2">
              <Icon name="file" className="shrink-0 text-slate-500" />
              <span className="truncate text-xs text-slate-300">{it.name}</span>
            </div>
            <span className="ml-2 shrink-0 font-mono-num text-xs text-slate-400">{formatBytes(it.size)}</span>
          </div>
        ))}
        {transfer.items.length > 6 && <p className="px-1 text-xs text-slate-400">+{transfer.items.length - 6}</p>}
      </div>

      <div className="h-2 w-full overflow-hidden rounded-full bg-white/5">
        <div className={`h-full rounded-full transition-[width] duration-200 ${done ? "bg-gradient-to-r from-emerald-400 to-teal-400" : "bg-gradient-to-r from-sky-400 to-cyan-400"}`}
          style={{ width: `${Math.min(100, pct)}%` }} />
      </div>
      <div className="mt-2 flex justify-between text-xs text-slate-400">
        <span className="font-mono-num">{formatBytes(transferred)} / {formatBytes(transfer.total)}</span>
        <span className="font-mono-num">
          {!done && speed > 0 ? `${formatBytes(speed)}${t("transfer.perSecSuffix")}` : ""}
          {!done && eta > 0 ? ` · ${eta}${t("transfer.leftSuffix")}` : ""}
          {done ? t("transfer.verified") : ""}
        </span>
      </div>
      {!done && (
        <button type="button" onClick={onCancel}
          className="mt-4 w-full rounded-xl border border-rose-300/20 bg-rose-500/10 px-4 py-2.5 text-sm font-medium text-rose-200 transition hover:bg-rose-500/20 active:scale-[0.99]">
          {t("transfer.cancel")}
        </button>
      )}
    </div>
  );
}

function Footer({ t }: { t: (k: string) => string }) {
  return (
    <div className="flex items-center justify-center gap-2 text-xs text-slate-400">
      <Icon name="lock" />
      <span>{t("footer.crypto")}</span>
    </div>
  );
}

function SettingsModal({ t, lang, setLang, theme, setTheme, config, saveDirLabel, history, formatBytes, onChooseSaveDir, onClose, onError, onSaved }: {
  t: (k: string) => string;
  lang: Lang; setLang: (l: Lang) => void;
  theme: Theme; setTheme: (t: Theme) => void;
  config: AppConfig | null; saveDirLabel: string;
  history: TransferRecord[];
  formatBytes: (n: number) => string;
  onChooseSaveDir: () => void; onClose: () => void;
  onError: (e: string) => void; onSaved: () => Promise<void>;
}) {
  const [name, setName] = useState(config?.deviceName ?? "");
  const [mailboxUrl, setMailboxUrl] = useState(config?.mailboxUrl ?? "");

  // Escape to close
  useEffect(() => {
    setName(config?.deviceName ?? "");
    setMailboxUrl(config?.mailboxUrl ?? "");
  }, [config?.deviceName, config?.mailboxUrl]);

  useEffect(() => {
    const h = (e: KeyboardEvent) => { if (e.key === "Escape") onClose(); };
    window.addEventListener("keydown", h);
    return () => window.removeEventListener("keydown", h);
  }, [onClose]);

  const saveName = async () => {
    if (!name.trim()) return;
    try { await invoke("set_device_name", { name: name.trim() }); await onSaved(); onClose(); }
    catch (e) { onError(String(e)); }
  };

  const saveMailboxUrl = async () => {
    try { await invoke("set_mailbox_url", { url: mailboxUrl.trim() }); await onSaved(); onClose(); }
    catch (e) { onError(String(e)); }
  };

  return (
    <div role="dialog" aria-modal="true" aria-labelledby="settings-title"
      className="absolute inset-0 z-50 flex items-center justify-center overflow-y-auto bg-black/60 p-6 backdrop-blur-sm" onClick={onClose}>
      <div className="frost-panel animate-fade-in my-auto w-full max-w-md max-h-full overflow-y-auto rounded-2xl p-6" onClick={(e) => e.stopPropagation()}>
        <div className="mb-5 flex items-center justify-between">
          <h2 id="settings-title" className="text-xl font-semibold text-sky-50">{t("settings.title")}</h2>
          <button onClick={onClose} aria-label={t("common.cancel")}
            className="rounded-lg p-1 text-slate-400 transition hover:bg-white/10 hover:text-slate-200 active:scale-95">
            <Icon name="close" />
          </button>
        </div>

        <div className="space-y-5">
          <div>
            <label className="mb-2 block text-xs font-medium uppercase tracking-wider text-slate-400">{t("settings.theme")}</label>
            <div className="frost-panel flex rounded-xl p-1">
              {(["system", "dark", "light"] as Theme[]).map((th) => (
                <button key={th} onClick={() => setTheme(th)}
                  className={`flex-1 rounded-lg px-3 py-2 text-sm font-medium transition ${
                    theme === th ? "bg-gradient-to-r from-sky-500/90 to-cyan-500/90 text-white" : "text-slate-400 hover:bg-white/5 hover:text-slate-200 active:scale-[0.97]"}`}>
                  {t(`settings.theme.${th}`)}
                </button>
              ))}
            </div>
          </div>

          <div>
            <label className="mb-2 block text-xs font-medium uppercase tracking-wider text-slate-400">{t("settings.language")}</label>
            <div className="frost-panel flex rounded-xl p-1">
              {(["tr", "en"] as Lang[]).map((l) => (
                <button key={l} onClick={() => setLang(l)}
                  className={`flex-1 rounded-lg px-4 py-2 text-sm font-medium uppercase transition ${
                    lang === l ? "bg-gradient-to-r from-sky-500/90 to-cyan-500/90 text-white" : "text-slate-400 hover:bg-white/5 hover:text-slate-200 active:scale-[0.97]"}`}>
                  {l === "tr" ? "Türkçe" : "English"}
                </button>
              ))}
            </div>
          </div>

          <div>
            <label className="mb-2 block text-xs font-medium uppercase tracking-wider text-slate-400">{t("settings.saveDir")}</label>
            <div className="flex items-center gap-2">
              <div title={saveDirLabel} className="font-mono-num min-w-0 flex-1 break-all rounded-xl border border-sky-300/15 bg-slate-950/50 px-3 py-2.5 text-sm text-slate-300">{saveDirLabel}</div>
              <button onClick={onChooseSaveDir}
                className="shrink-0 rounded-xl bg-sky-400/15 px-4 py-2.5 text-sm font-medium text-sky-100 transition hover:bg-sky-400/25 active:scale-[0.98]">
                {t("settings.saveDirChoose")}
              </button>
            </div>
          </div>

          <div>
            <label className="mb-2 block text-xs font-medium uppercase tracking-wider text-slate-400">{t("settings.deviceName")}</label>
            <div className="flex gap-2">
              <input id="device-name" value={name} aria-label={t("settings.deviceName")}
                onChange={(e) => setName(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && saveName()}
                placeholder={t("settings.deviceNamePlaceholder")}
                className="min-w-0 flex-1 rounded-xl border border-sky-300/15 bg-slate-950/50 px-3 py-2.5 text-sm text-sky-50 outline-none transition focus-visible:border-sky-400/60" />
              <button onClick={saveName} disabled={!name.trim()}
                className="shrink-0 rounded-xl bg-sky-400/15 px-4 py-2.5 text-sm font-medium text-sky-100 transition enabled:hover:bg-sky-400/25 active:scale-[0.98] disabled:opacity-40">
                {t("settings.deviceNameSave")}
              </button>
            </div>
          </div>

          <div>
            <label className="mb-2 block text-xs font-medium uppercase tracking-wider text-slate-400">{t("settings.mailboxUrl")}</label>
            <div className="flex gap-2">
              <input id="mailbox-url" value={mailboxUrl} aria-label={t("settings.mailboxUrl")}
                onChange={(e) => setMailboxUrl(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && saveMailboxUrl()}
                placeholder={t("settings.mailboxUrlPlaceholder")}
                className="font-mono-num min-w-0 flex-1 rounded-xl border border-sky-300/15 bg-slate-950/50 px-3 py-2.5 text-sm text-sky-50 outline-none transition focus-visible:border-sky-400/60" />
              <button onClick={saveMailboxUrl}
                className="shrink-0 rounded-xl bg-sky-400/15 px-4 py-2.5 text-sm font-medium text-sky-100 transition hover:bg-sky-400/25 active:scale-[0.98]">
                {t("settings.mailboxUrlSave")}
              </button>
            </div>
            <p className="mt-1.5 text-xs text-slate-500">{t("settings.mailboxUrlHint")}</p>
          </div>

          <div>
            <label className="mb-2 block text-xs font-medium uppercase tracking-wider text-slate-400">{t("settings.history")}</label>
            {history.length === 0 ? (
              <p className="text-sm text-slate-500">{t("settings.historyEmpty")}</p>
            ) : (
              <ul className="max-h-36 space-y-1 overflow-auto text-xs text-slate-400">
                {history.slice(0, 12).map((h) => (
                  <li key={h.id} className="rounded-lg bg-white/[0.03] px-3 py-2">
                    {t("settings.historyEntry")
                      .replace("{dir}", h.direction === "sending" ? "↑" : "↓")
                      .replace("{n}", String(h.fileCount))
                      .replace("{size}", formatBytes(h.totalBytes))}
                    {" · "}{h.ok ? t("settings.historyOk") : t("settings.historyFail")}
                  </li>
                ))}
              </ul>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

function PeerPickerModal({ peers, t, onPick, onCancel }: {
  peers: DiscoveredPeer[];
  t: (k: string) => string;
  onPick: (p: DiscoveredPeer) => void;
  onCancel: () => void;
}) {
  useEffect(() => {
    const h = (e: KeyboardEvent) => { if (e.key === "Escape") onCancel(); };
    window.addEventListener("keydown", h);
    return () => window.removeEventListener("keydown", h);
  }, [onCancel]);

  return (
    <div role="dialog" aria-modal="true" aria-labelledby="peer-picker-title"
      className="absolute inset-0 z-[55] flex items-center justify-center overflow-y-auto bg-black/70 p-6 backdrop-blur-sm">
      <div className="frost-panel animate-fade-in my-auto w-full max-w-md rounded-2xl p-6">
        <h2 id="peer-picker-title" className="text-xl font-semibold text-sky-50">{t("join.pickPeer")}</h2>
        <p className="mt-2 text-sm text-muted">{t("join.pickPeerDesc")}</p>
        <ul className="mt-4 space-y-2">
          {peers.map((p) => (
            <li key={`${p.address}:${p.port}`}>
              <button type="button" onClick={() => onPick(p)}
                className="w-full rounded-xl border border-sky-300/15 bg-white/[0.04] px-4 py-3 text-left transition hover:bg-white/[0.08] active:scale-[0.99]">
                <span className="block text-sm font-medium text-sky-50">{p.displayName}</span>
                <span className="font-mono-num text-xs text-slate-500">{p.address}:{p.port}</span>
              </button>
            </li>
          ))}
        </ul>
        <button type="button" onClick={onCancel}
          className="mt-4 w-full rounded-xl px-4 py-2.5 text-sm text-slate-400 transition hover:bg-white/5 hover:text-slate-200">
          {t("common.cancel")}
        </button>
      </div>
    </div>
  );
}

function PendingTransferModal({ transfer, t, formatBytes, onAccept, onReject }: {
  transfer: TransferStart;
  t: (k: string) => string;
  formatBytes: (n: number) => string;
  onAccept: () => void;
  onReject: () => void;
}) {
  const fileWord = transfer.file_count === 1 ? t("transfer.fileOne") : t("transfer.fileMany");

  useEffect(() => {
    const h = (e: KeyboardEvent) => { if (e.key === "Escape") onReject(); };
    window.addEventListener("keydown", h);
    return () => window.removeEventListener("keydown", h);
  }, [onReject]);

  return (
    <div role="dialog" aria-modal="true" aria-labelledby="pending-transfer-title"
      className="absolute inset-0 z-[60] flex items-center justify-center overflow-y-auto bg-black/70 p-6 backdrop-blur-sm">
      <div className="frost-panel animate-fade-in my-auto w-full max-w-md max-h-full overflow-y-auto rounded-2xl p-6">
        <h2 id="pending-transfer-title" className="text-xl font-semibold text-sky-50">{t("transfer.pending.title")}</h2>
        <p className="mt-2 text-sm text-muted">{t("transfer.pending.desc")}</p>
        <p className="mt-4 text-xs text-slate-500">{transfer.file_count} {fileWord} · {formatBytes(transfer.total)}</p>
        <div className="mt-3 max-h-40 space-y-1 overflow-auto">
          {transfer.items.map((it, i) => (
            <div key={i} className="flex items-center justify-between rounded-lg bg-white/[0.03] px-3 py-1.5 text-xs">
              <span className="truncate text-slate-300">{it.name}</span>
              <span className="ml-2 shrink-0 font-mono-num text-slate-500">{formatBytes(it.size)}</span>
            </div>
          ))}
        </div>
        <div className="mt-6 flex gap-2">
          <button type="button" onClick={onReject}
            className="flex-1 rounded-xl border border-sky-300/15 bg-white/[0.04] px-4 py-3 text-sm font-medium text-slate-300 transition hover:bg-white/[0.08] active:scale-[0.99]">
            {t("transfer.pending.reject")}
          </button>
          <button type="button" onClick={onAccept}
            className="frost-glow flex-1 rounded-xl bg-gradient-to-r from-sky-400 via-sky-500 to-cyan-500 px-4 py-3 text-sm font-medium text-white transition hover:brightness-110 active:scale-[0.99]">
            {t("transfer.pending.accept")}
          </button>
        </div>
      </div>
    </div>
  );
}

/* ---------- icons (consistent Feather-style, strokeWidth 2) ---------- */
function Icon({ name, className = "" }: { name: "upload" | "download" | "file" | "lock" | "alert" | "gear" | "close" | "check" | "info"; className?: string }) {
  const base = { viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", strokeWidth: 2, strokeLinecap: "round" as const, strokeLinejoin: "round" as const, className };
  switch (name) {
    case "upload": return <svg {...base} width={18} height={18}><path d="M12 16V4M7 9l5-5 5 5M5 20h14" /></svg>;
    case "download": return <svg {...base} width={18} height={18}><path d="M12 4v12M7 11l5 5 5-5M5 20h14" /></svg>;
    case "file": return <svg {...base} width={14} height={14}><path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z" /><path d="M14 3v5h5" /></svg>;
    case "lock": return <svg {...base} width={12} height={12}><rect x="4" y="11" width="16" height="9" rx="2" /><path d="M8 11V8a4 4 0 0 1 8 0v3" /></svg>;
    case "alert": return <svg {...base} width={16} height={16}><path d="M12 9v4M12 17h.01M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z" /></svg>;
    case "gear": return <svg {...base} width={16} height={16}><circle cx="12" cy="12" r="3" /><path d="M12 2v3M12 19v3M4.2 4.2l2.1 2.1M17.7 17.7l2.1 2.1M2 12h3M19 12h3M4.2 19.8l2.1-2.1M17.7 6.3l2.1-2.1" /></svg>;
    case "close": return <svg {...base} width={18} height={18}><path d="M18 6 6 18M6 6l12 12" /></svg>;
    case "check": return <svg {...base} width={14} height={14}><path d="M20 6 9 17l-5-5" /></svg>;
    case "info": return <svg {...base} width={14} height={14}><circle cx="12" cy="12" r="9" /><path d="M12 11v5M12 8h.01" /></svg>;
  }
}
