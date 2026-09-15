import { useCallback, useEffect, useRef, useState, type RefObject } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import { getCurrentWebview } from "@tauri-apps/api/webview";
import { open } from "@tauri-apps/plugin-dialog";
import brand from "./assets/brand.png";
import { translateError } from "./errors";
import { appendHistory, loadHistory, type TransferRecord } from "./history";
import { useI18n, type Lang } from "./i18n";
import { applyTheme, readTheme, saveTheme, watchSystemTheme, type Theme } from "./theme";
import { INVITE_PASTE_MAX, lanCodeFromInput, looksLikeInvite } from "./invite";

type Phase = "idle" | "hosting" | "joining" | "connected";
type Mode = "host" | "join";
type Net = "lan" | "internet";

interface TransferItem { name: string; size: number; }
interface TransferStart {
  direction: "sending" | "receiving";
  items: TransferItem[];
  total: number;
  file_count: number;
  epoch?: number;
}
interface Progress {
  transferred: number; total: number; percent: number;
  direction: "sending" | "receiving";
  epoch?: number;
}
interface TransferDonePayload { ok: boolean; epoch?: number; error?: string; }
interface NoticePayload { message: string; epoch?: number; }
interface ReceivedPayload { dest: string; epoch?: number; }
interface Toast { id: number; kind: "ok" | "err" | "info"; msg: string; }
interface AppConfig { downloadDir: string | null; deviceName: string | null; mailboxUrl: string | null; remoteAvailable: boolean; }
interface DiscoveredPeer { displayName: string; address: string; port: number; }
interface PairedPayload { peerName: string | null; localName: string | null; epoch?: number; }
interface InvitePayload { invite: string; code: string; hasRelay?: boolean; mailboxOk?: boolean; epoch?: number; }
interface PairingPayload { on: boolean; epoch: number; }
interface ErrorPayload { message: string; epoch?: number; }
interface DisconnectPayload { epoch?: number; }

type EpochGateEvt =
  | { kind: "invite"; p: InvitePayload }
  | { kind: "error"; p: ErrorPayload | string }
  | { kind: "disconnected"; p: DisconnectPayload | string }
  | { kind: "paired"; p: PairedPayload }
  | { kind: "pairing"; p: PairingPayload };

function evtEpoch(ev: EpochGateEvt): number | undefined {
  switch (ev.kind) {
    case "invite":
    case "paired":
    case "pairing":
      return ev.p.epoch;
    case "error":
    case "disconnected":
      return typeof ev.p === "object" && ev.p && typeof ev.p.epoch === "number" ? ev.p.epoch : undefined;
  }
}

const STEP = 30;
/** Incoming-file prompt. Lockstep `commands.rs` `DECISION_TIMEOUT` (SAS + review). */
const DECISION_SECS = 6 * 60;

function useFocusTrap(active: boolean, containerRef: RefObject<HTMLElement | null>) {
  useEffect(() => {
    if (!active || !containerRef.current) return;
    const root = containerRef.current;
    const selector = 'button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), a[href], [tabindex]:not([tabindex="-1"])';
    const focusable = () => Array.from(root.querySelectorAll<HTMLElement>(selector));
    const first = () => focusable()[0];
    first()?.focus();
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== "Tab") return;
      const nodes = focusable();
      if (nodes.length === 0) return;
      const f = nodes[0];
      const l = nodes[nodes.length - 1];
      if (e.shiftKey && document.activeElement === f) {
        e.preventDefault();
        l.focus();
      } else if (!e.shiftKey && document.activeElement === l) {
        e.preventDefault();
        f.focus();
      }
    };
    root.addEventListener("keydown", onKey);
    return () => root.removeEventListener("keydown", onKey);
  }, [active, containerRef]);
}

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  const u = ["KB", "MB", "GB", "TB"];
  let v = n / 1024, i = 0;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return `${v.toFixed(v >= 100 ? 0 : 1)} ${u[i]}`;
}

function relativeTime(at: number, t: (k: string) => string): string | null {
  const sec = Math.max(0, Math.floor((Date.now() - at) / 1000));
  if (sec < 45) return t("settings.historyJustNow");
  const min = Math.floor(sec / 60);
  if (min < 60) return t("settings.historyMinutes").replace("{n}", String(min));
  const hr = Math.floor(min / 60);
  if (hr < 24) return t("settings.historyHours").replace("{n}", String(hr));
  const day = Math.floor(hr / 24);
  if (day < 7) return t("settings.historyDays").replace("{n}", String(day));
  return null;
}

function copyText(text: string): Promise<boolean> {
  const fallback = (): boolean => {
    const ta = document.createElement("textarea");
    ta.value = text;
    ta.setAttribute("readonly", "");
    ta.style.position = "fixed";
    ta.style.left = "-9999px";
    document.body.appendChild(ta);
    ta.select();
    let ok = false;
    try { ok = document.execCommand("copy"); } catch { /* ignore */ }
    document.body.removeChild(ta);
    return ok;
  };
  if (navigator.clipboard?.writeText) {
    return navigator.clipboard.writeText(text).then(() => true).catch(() => fallback());
  }
  return Promise.resolve(fallback());
}
function basename(p: string): string {
  const parts = p.replace(/\\/g, "/").split("/");
  return parts[parts.length - 1] || p;
}

function peerEndpoint(p: DiscoveredPeer): string {
  return p.address.includes(":") ? `[${p.address}]:${p.port}` : `${p.address}:${p.port}`;
}

export default function App() {
  const { t, lang, setLang } = useI18n();

  const [phase, setPhase] = useState<Phase>("idle");
  const [mode, setMode] = useState<Mode>("host");
  const [net, setNet] = useState<Net>("lan");
  const [code, setCode] = useState("");
  const [invite, setInvite] = useState("");
  const [inviteHasRelay, setInviteHasRelay] = useState(true);
  const [inviteMailboxOk, setInviteMailboxOk] = useState(false);
  const [joinCode, setJoinCode] = useState("");
  const [liveness, setLiveness] = useState("");
  const [secLeft, setSecLeft] = useState(STEP);
  const [copied, setCopied] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busySec, setBusySec] = useState(0);

  const [transfer, setTransfer] = useState<TransferStart | null>(null);
  const [progress, setProgress] = useState<Progress | null>(null);
  const [transferDone, setTransferDone] = useState(false);
  const [speed, setSpeed] = useState(0);

  const [dragging, setDragging] = useState(false);
  const [toasts, setToasts] = useState<Toast[]>([]);

  const [config, setConfig] = useState<AppConfig | null>(null);
  const [showSettings, setShowSettings] = useState(false);
  const [pendingTransfer, setPendingTransfer] = useState<TransferStart | null>(null);
  const [pendingLeft, setPendingLeft] = useState(DECISION_SECS);
  const [acceptLeft, setAcceptLeft] = useState(DECISION_SECS);
  const [peerChoices, setPeerChoices] = useState<DiscoveredPeer[] | null>(null);
  const [peerName, setPeerName] = useState<string | null>(null);
  const [localName, setLocalName] = useState<string | null>(null);
  const [sasOk, setSasOk] = useState(false);
  const [pairing, setPairing] = useState(false);
  const [joinDial, setJoinDial] = useState(false);
  const [sendPrep, setSendPrep] = useState(false);
  const [recvPrep, setRecvPrep] = useState(false);
  const [xferLive, setXferLive] = useState(false);
  const [xferStalled, setXferStalled] = useState(false);
  const [disconnectAsk, setDisconnectAsk] = useState(false);
  const [history, setHistory] = useState<TransferRecord[]>(() => loadHistory());
  const [theme, setThemeState] = useState<Theme>(() => readTheme());

  const phaseRef = useRef(phase);
  phaseRef.current = phase;
  const sasOkRef = useRef(sasOk);
  sasOkRef.current = sasOk;
  const recvPrepRef = useRef(recvPrep);
  recvPrepRef.current = recvPrep;
  const pendingRef = useRef(pendingTransfer);
  pendingRef.current = pendingTransfer;
  const inviteRef = useRef(invite);
  inviteRef.current = invite;
  const transferRef = useRef(transfer);
  transferRef.current = transfer;
  const transferDoneRef = useRef(false);
  const sendLock = useRef(false);
  const speedRef = useRef({ at: 0, bytes: 0, speed: 0 });
  const progressAt = useRef(0);
  const toastId = useRef(0);
  const copyGen = useRef(0);
  const transferUiGen = useRef(0);
  const opGen = useRef(0);
  const liveEpoch = useRef<number | null>(null);
  const pendingEpochEvts = useRef<EpochGateEvt[]>([]);
  const relayHuntStarted = useRef<number | null>(null);
  const errorRef = useRef<HTMLDivElement>(null);

  const pushToast = useCallback((kind: Toast["kind"], msg: string) => {
    const id = ++toastId.current;
    setToasts((s) => [...s, { id, kind, msg }].slice(-3));
    setTimeout(() => setToasts((s) => s.filter((x) => x.id !== id)), 4200);
  }, []);

  const showError = useCallback((raw: string) => {
    setError(translateError(raw, t));
  }, [t]);

  const applyInvitePayload = useCallback((p: InvitePayload) => {
    if (inviteRef.current && p.invite !== inviteRef.current) {
      pushToast("ok", t("waiting.inviteRefreshed"));
    }
    copyGen.current += 1;
    setCopied(false);
    if (p.hasRelay === false) {
      if (relayHuntStarted.current == null) relayHuntStarted.current = Date.now();
    } else {
      relayHuntStarted.current = null;
    }
    inviteRef.current = p.invite;
    setInvite(p.invite);
    if (p.code) setCode(p.code);
    setInviteHasRelay(p.hasRelay !== false);
    setInviteMailboxOk(p.mailboxOk === true);
  }, [pushToast, t]);

  const refreshConfig = useCallback(async () => {
    try { setConfig(await invoke<AppConfig>("get_config")); } catch { /* ignore */ }
  }, []);

  const reset = useCallback((msgKey?: string, keepJoin = false) => {
    phaseRef.current = "idle";
    setPhase("idle"); setLiveness(""); setTransfer(null); setProgress(null);
    setTransferDone(false); setCode(""); setInvite(""); setInviteHasRelay(true); setInviteMailboxOk(false);
    if (!keepJoin) setJoinCode("");
    setPendingTransfer(null);
    setPeerChoices(null); setPeerName(null); setLocalName(null); setSasOk(false);
    setError(null); setPairing(false); setJoinDial(false); setSendPrep(false); setRecvPrep(false); setXferLive(false);
    setXferStalled(false);
    transferDoneRef.current = false;
    setDisconnectAsk(false);
    setShowSettings(false);
    sendLock.current = false;
    opGen.current += 1;
    liveEpoch.current = null;
    pendingEpochEvts.current = [];
    relayHuntStarted.current = null; copyGen.current += 1; transferUiGen.current += 1; setCopied(false);
    speedRef.current = { at: 0, bytes: 0, speed: 0 };
    if (msgKey) pushToast("info", t(msgKey));
  }, [pushToast, t]);

  const onPairedEvt = useCallback((p: PairedPayload) => {
    if (phaseRef.current !== "hosting" && phaseRef.current !== "joining") return;
    phaseRef.current = "connected";
    setPhase("connected"); setTransfer(null); setProgress(null); setTransferDone(false);
    transferDoneRef.current = false;
    setSasOk(false); setPairing(false); setShowSettings(false);
    setPeerName(p.peerName); setLocalName(p.localName);
    pushToast("ok", t("toast.connected"));
  }, [pushToast, t]);

  const onPairingEvt = useCallback((p: PairingPayload) => {
    if (phaseRef.current !== "hosting" && phaseRef.current !== "joining") return;
    setPairing(p.on);
  }, []);

  const onDisconnectEvt = useCallback((_p: DisconnectPayload | string) => {
    if (phaseRef.current === "idle") return;
    reset("toast.disconnected");
  }, [reset]);

  const onErrorEvt = useCallback((e: ErrorPayload | string) => {
    if (phaseRef.current === "idle") return;
    const msg = typeof e === "string" ? e : e?.message;
    if (!msg) return;
    if (/pairing cancelled/i.test(String(msg))) {
      reset();
      return;
    }
    const keepJoin = phaseRef.current === "joining";
    reset(undefined, keepJoin);
    showError(msg);
  }, [reset, showError]);

  const flushPendingEpoch = useCallback(() => {
    const epoch = liveEpoch.current;
    const q = pendingEpochEvts.current;
    pendingEpochEvts.current = [];
    if (typeof epoch !== "number" || epoch < 0) return;
    for (const ev of q) {
      if (liveEpoch.current !== epoch) return;
      const e = evtEpoch(ev);
      if (typeof e === "number" && e !== epoch) continue;
      switch (ev.kind) {
        case "invite": applyInvitePayload(ev.p); break;
        case "paired": onPairedEvt(ev.p); break;
        case "pairing": onPairingEvt(ev.p); break;
        case "disconnected": onDisconnectEvt(ev.p); break;
        case "error": onErrorEvt(ev.p); break;
      }
    }
  }, [applyInvitePayload, onDisconnectEvt, onErrorEvt, onPairedEvt, onPairingEvt]);

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
      else setRecvPrep(true);
    } catch (e) {
      const raw = String(e);
      if (/no pending transfer/i.test(raw) || /already handled/i.test(raw)) {
        setPendingTransfer(null);
        return;
      }
      showError(raw);
    }
  }, [pushToast, showError, t]);

  useEffect(() => { refreshConfig(); }, [refreshConfig]);

  // global event listeners (StrictMode-safe)
  useEffect(() => {
    let cancelled = false;
    let unlistens: UnlistenFn[] = [];
    (async () => {
      try {
        const add = <T,>(name: string, h: (p: T) => void) =>
          listen<T>(name, (e) => !cancelled && h(e.payload as T));
        const acceptEpoch = (e: number | undefined) => {
          if (liveEpoch.current == null || liveEpoch.current === -1) return false;
          if (typeof e !== "number") return true;
          return liveEpoch.current === e;
        };
        unlistens.push(await add<PairedPayload>("frostwall://paired", (p) => {
          if (liveEpoch.current === -1) {
            pendingEpochEvts.current.push({ kind: "paired", p });
            return;
          }
          if (!acceptEpoch(p.epoch)) return;
          onPairedEvt(p);
        }));
        unlistens.push(await add<PairingPayload>("frostwall://pairing", (p) => {
          if (liveEpoch.current === -1) {
            pendingEpochEvts.current.push({ kind: "pairing", p });
            return;
          }
          if (!acceptEpoch(p.epoch)) return;
          onPairingEvt(p);
        }));
        unlistens.push(await add<TransferStart>("frostwall://transfer-pending", (tr) => {
          if (phaseRef.current !== "connected") return;
          if (!acceptEpoch(tr.epoch)) return;
          setShowSettings(false);
          setPendingTransfer(tr);
        }));
        unlistens.push(await add<Progress>("frostwall://progress", (p) => {
          if (phaseRef.current !== "connected") return;
          if (!acceptEpoch(p.epoch)) return;
          if (transferDoneRef.current) return;
          const now = performance.now();
          const r = speedRef.current;
          const dt = (now - r.at) / 1000;
          if (r.at > 0 && dt > 0) {
            const inst = (p.transferred - r.bytes) / dt;
            r.speed = r.speed * 0.7 + inst * 0.3;
          }
          r.at = now; r.bytes = p.transferred; setSpeed(r.speed); setProgress(p); setXferLive(true);
          progressAt.current = now;
        }));
        unlistens.push(await add<TransferStart>("frostwall://transfer-start", (tr) => {
          if (phaseRef.current !== "connected") return;
          if (!acceptEpoch(tr.epoch)) return;
          transferUiGen.current += 1;
          speedRef.current = { at: 0, bytes: 0, speed: 0 };
          progressAt.current = performance.now();
          setSpeed(0);
          setSendPrep(false);
          setRecvPrep(false);
          setXferLive(false);
          setXferStalled(false);
          transferDoneRef.current = false;
          setTransfer(tr); setTransferDone(false);
          setProgress({ transferred: 0, total: tr.total, percent: 0, direction: tr.direction });
        }));
        unlistens.push(await add<TransferDonePayload | boolean>("frostwall://transfer-done", (p) => {
          if (phaseRef.current !== "connected") return;
          const ok = typeof p === "boolean" ? p : p?.ok;
          const epoch = typeof p === "object" && p && typeof p.epoch === "number" ? p.epoch : undefined;
          if (!acceptEpoch(epoch)) return;
          const tr = transferRef.current;
          const err = typeof p === "object" && p && typeof p.error === "string" ? p.error : undefined;
          transferDoneRef.current = true;
          if (tr) {
            setHistory(appendHistory({
              direction: tr.direction,
              fileCount: tr.file_count,
              totalBytes: tr.total,
              ok: ok === true,
              err: ok === true ? undefined : err,
            }));
          }
          if (!ok) {
            transferUiGen.current += 1;
            setTransfer(null); setProgress(null); setSpeed(0); setPendingTransfer(null);
            setSendPrep(false);
            setRecvPrep(false);
            setXferLive(false);
            setXferStalled(false);
            return;
          }
          const gen = ++transferUiGen.current;
          setTransferDone(true);
          setXferLive(false);
          setSendPrep(false);
          setRecvPrep(false);
          setTimeout(() => {
            if (transferUiGen.current !== gen) return;
            setTransfer(null); setProgress(null); setTransferDone(false);
            setXferLive(false);
          }, 1600);
        }));
        unlistens.push(await add<ReceivedPayload | string>("frostwall://received", (p) => {
          if (phaseRef.current !== "connected") return;
          const dest = typeof p === "string" ? p : p?.dest;
          const epoch = typeof p === "object" && p && typeof p.epoch === "number" ? p.epoch : undefined;
          if (!dest) return;
          if (!acceptEpoch(epoch)) return;
          pushToast("ok", t("toast.savedTo").replace("{x}", basename(dest)));
        }));
        unlistens.push(await add<InvitePayload>("frostwall://invite", (p) => {
          if (phaseRef.current !== "hosting") return;
          if (liveEpoch.current === -1) {
            pendingEpochEvts.current.push({ kind: "invite", p });
            return;
          }
          if (!acceptEpoch(p.epoch)) return;
          applyInvitePayload(p);
        }));
        unlistens.push(await add<DisconnectPayload | string>("frostwall://disconnected", (p) => {
          if (liveEpoch.current === -1) {
            pendingEpochEvts.current.push({ kind: "disconnected", p });
            return;
          }
          const epoch = typeof p === "object" && p && typeof p.epoch === "number" ? p.epoch : undefined;
          if (!acceptEpoch(epoch)) return;
          onDisconnectEvt(p);
        }));
        unlistens.push(await add<ErrorPayload | string>("frostwall://error", (e) => {
          const msg = typeof e === "string" ? e : e?.message;
          if (!msg) return;
          if (liveEpoch.current === -1) {
            pendingEpochEvts.current.push({ kind: "error", p: e });
            return;
          }
          const epoch = typeof e === "object" && e && typeof e.epoch === "number" ? e.epoch : undefined;
          if (!acceptEpoch(epoch)) return;
          onErrorEvt(e);
        }));
        unlistens.push(await add<NoticePayload | string>("frostwall://notice", (e) => {
          if (phaseRef.current !== "connected") return;
          const msg = typeof e === "string" ? e : e?.message;
          const epoch = typeof e === "object" && e && typeof e.epoch === "number" ? e.epoch : undefined;
          if (!msg) return;
          if (!acceptEpoch(epoch)) return;
          pushToast("err", translateError(msg, t));
        }));
      } catch {
        /* vite preview: no Tauri runtime */
      }
    })();
    return () => { cancelled = true; unlistens.forEach((u) => u()); };
  }, [applyInvitePayload, onDisconnectEvt, onErrorEvt, onPairedEvt, onPairingEvt, pushToast, t]);

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
    if (paths.length === 0 || !sasOkRef.current) return;
    if (phaseRef.current !== "connected") return;
    if (sendLock.current || transferRef.current || recvPrepRef.current || pendingRef.current) return;
    sendLock.current = true;
    setError(null);
    setSendPrep(true);
    try { await invoke("send_files", { paths }); }
    catch (e) {
      const raw = String(e);
      const lower = raw.toLowerCase();
      if (lower.includes("transfer cancelled") && !lower.includes("by peer") && !lower.includes("session ended")) return;
      if (phaseRef.current !== "connected") return;
      pushToast("err", translateError(raw, t));
    } finally {
      sendLock.current = false;
      setSendPrep(false);
    }
  }, [pushToast, t]);

  useEffect(() => {
    let gone = false;
    let stop: UnlistenFn | undefined;
    void (async () => {
      try {
        const w = getCurrentWebview();
        const un = await w.onDragDropEvent(async (e) => {
          if (e.payload.type === "enter" || e.payload.type === "over") {
            if (
              phaseRef.current === "connected"
              && sasOkRef.current
              && !transferRef.current
              && !recvPrepRef.current
              && !pendingRef.current
            ) setDragging(true);
          } else if (e.payload.type === "leave") setDragging(false);
          else if (e.payload.type === "drop") {
            setDragging(false);
            if (
              phaseRef.current === "connected"
              && sasOkRef.current
              && !transferRef.current
              && !recvPrepRef.current
              && !pendingRef.current
            ) await send(e.payload.paths);
          }
        });
        if (gone) { un(); return; }
        stop = un;
      } catch {
        /* vite preview: no Tauri webview */
      }
    })();
    return () => { gone = true; stop?.(); };
  }, [send]);

  const startHost = useCallback(async () => {
    if (phaseRef.current !== "idle") return;
    phaseRef.current = "hosting";
    const gen = opGen.current;
    setError(null);
    liveEpoch.current = -1;
    pendingEpochEvts.current = [];
    inviteRef.current = "";
    setInvite("");
    setPhase("hosting");
    try {
      const c = await invoke<string>("generate_code");
      if (gen !== opGen.current) return;
      setCode(c);
      if (net === "internet") {
        setInviteHasRelay(true);
        setInviteMailboxOk(false);
        relayHuntStarted.current = null;
        const p = await invoke<InvitePayload>("host_start_internet", { code: c });
        if (gen !== opGen.current) return;
        if (typeof p.epoch === "number") liveEpoch.current = p.epoch;
        flushPendingEpoch();
        if (liveEpoch.current === p.epoch && !inviteRef.current) {
          applyInvitePayload(p);
        }
      } else {
        const ep = await invoke<number>("host_start", { code: c });
        if (gen !== opGen.current) return;
        if (typeof ep === "number") liveEpoch.current = ep;
        flushPendingEpoch();
      }
    } catch (e) {
      if (gen !== opGen.current) return;
      liveEpoch.current = null;
      pendingEpochEvts.current = [];
      phaseRef.current = "idle";
      showError(String(e)); setPhase("idle");
    }
  }, [applyInvitePayload, flushPendingEpoch, net, showError]);

  const startJoin = useCallback(async () => {
    if (phaseRef.current !== "idle") return;
    const gen = opGen.current;
    const trimmed = joinCode.trim();
    const invitePaste = looksLikeInvite(trimmed);
    const remote = net === "internet" || invitePaste;
    if (remote) {
      if (!trimmed) {
        showError(t((config?.remoteAvailable ?? false) ? "join.errorInviteOrCode" : "join.errorInvite"));
        return;
      }
      phaseRef.current = "joining";
      setNet("internet");
      setError(null); setPhase("joining"); setPeerChoices(null);
      liveEpoch.current = -1;
      pendingEpochEvts.current = [];
      setJoinDial(false);
      try {
        const ep = await invoke<number>("join_internet", { invite: trimmed });
        if (gen !== opGen.current) return;
        if (typeof ep === "number") liveEpoch.current = ep;
        flushPendingEpoch();
      } catch (e) {
        if (gen !== opGen.current) return;
        liveEpoch.current = null;
        pendingEpochEvts.current = [];
        phaseRef.current = "idle";
        showError(String(e)); setPhase("idle");
      }
      return;
    }
    const lanDigits = lanCodeFromInput(joinCode);
    if (lanDigits.length !== 6) { showError(t("join.error6")); return; }
    phaseRef.current = "joining";
    setError(null); setPhase("joining"); setPeerChoices(null);
    liveEpoch.current = -1;
    pendingEpochEvts.current = [];
    setJoinDial(false);
    try {
      const peers = await invoke<DiscoveredPeer[]>("discover_peers");
      if (gen !== opGen.current) return;
      if (peers.length === 0) {
        liveEpoch.current = null;
        pendingEpochEvts.current = [];
        phaseRef.current = "idle";
        showError(t("err.noPeer"));
        setPhase("idle");
        return;
      }
      if (peers.length === 1) {
        setJoinDial(true);
        const ep = await invoke<number>("join_peer", {
          code: lanDigits,
          address: peers[0].address,
          port: peers[0].port,
          displayName: peers[0].displayName,
        });
        if (gen !== opGen.current) return;
        if (typeof ep === "number") liveEpoch.current = ep;
        flushPendingEpoch();
        return;
      }
      setPeerChoices(peers);
    } catch (e) {
      if (gen !== opGen.current) return;
      liveEpoch.current = null;
      pendingEpochEvts.current = [];
      phaseRef.current = "idle";
      showError(String(e)); setPhase("idle");
    }
  }, [joinCode, net, showError, t, config?.remoteAvailable, flushPendingEpoch]);

  const connectToPeer = useCallback(async (peer: DiscoveredPeer) => {
    const lanDigits = lanCodeFromInput(joinCode);
    if (lanDigits.length !== 6) { showError(t("join.error6")); return; }
    const gen = opGen.current;
    setPeerChoices(null);
    phaseRef.current = "joining";
    setPhase("joining");
    setJoinDial(true);
    liveEpoch.current = -1;
    try {
      const ep = await invoke<number>("join_peer", {
        code: lanDigits,
        address: peer.address,
        port: peer.port,
        displayName: peer.displayName,
      });
      if (gen !== opGen.current) return;
      if (typeof ep === "number") liveEpoch.current = ep;
      flushPendingEpoch();
    } catch (e) {
      if (gen !== opGen.current) return;
      liveEpoch.current = null;
      pendingEpochEvts.current = [];
      reset(undefined, true);
      showError(String(e));
    }
  }, [joinCode, showError, t, flushPendingEpoch, reset]);

  const cancelTransfer = useCallback(async () => {
    try {
      await invoke("cancel_transfer");
      pushToast("info", t("toast.transferCancelled"));
    } catch (e) {
      if (/no transfer in progress/i.test(String(e))) return;
      showError(String(e));
    }
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
    setDisconnectAsk(false);
    opGen.current += 1;
    phaseRef.current = "idle";
    await invoke("disconnect").catch(() => {});
    reset();
  }, [reset]);

  const requestDisconnect = useCallback(() => {
    if (phaseRef.current === "connected" && (transferRef.current || sendPrep || recvPrep || pendingTransfer || xferLive)) {
      setDisconnectAsk(true);
      return;
    }
    void doDisconnect();
  }, [doDisconnect, sendPrep, recvPrep, pendingTransfer, xferLive]);

  const copyShown = useCallback((text: string) => {
    if (!text) return;
    const gen = ++copyGen.current;
    void copyText(text).then((ok) => {
      if (ok) {
        setCopied(true);
        setTimeout(() => { if (copyGen.current === gen) setCopied(false); }, 1500);
      } else {
        pushToast("err", t("toast.copyFailed"));
      }
    });
  }, [pushToast, t]);

  const copyInvite = useCallback(() => {
    copyShown(net === "internet" ? invite : code);
  }, [copyShown, invite, code, net]);

  const pasteJoin = useCallback(async () => {
    try {
      const raw = await navigator.clipboard.readText();
      const next = raw.slice(0, INVITE_PASTE_MAX);
      if (!next.trim()) {
        pushToast("err", t("toast.pasteFailed"));
        return;
      }
      if (looksLikeInvite(next)) {
        setNet("internet");
        setJoinCode(next);
        return;
      }
      if (net === "lan") {
        setJoinCode(lanCodeFromInput(next).slice(0, 6));
        return;
      }
      const digits = next.replace(/\s/g, "");
      setJoinCode(/^\d{6}$/.test(digits) ? digits : next);
    } catch {
      pushToast("err", t("toast.pasteFailed"));
    }
  }, [net, pushToast, t]);

  const chooseSaveDir = useCallback(async () => {
    if (transferRef.current || recvPrepRef.current) return;
    const r = await open({ directory: true });
    if (!r) return;
    await invoke("set_download_dir", { path: String(r) });
    await refreshConfig();
    pushToast("ok", t("toast.saveDirUpdated"));
  }, [refreshConfig, pushToast, t]);

  const saveDirLabel = config?.downloadDir ?? t("settings.saveDirDefault");
  const mailboxOn = config?.remoteAvailable ?? false;
  const modalOpen = showSettings || (!!pendingTransfer && sasOk) || (peerChoices != null && peerChoices.length > 1) || disconnectAsk;

  const busy = phase === "hosting" || phase === "joining";
  const eta = progress && speed > 0 ? Math.ceil((progress.total - progress.transferred) / speed) : 0;
  const pct = progress ? progress.percent : 0;

  useEffect(() => {
    if (!busy) { setBusySec(0); return; }
    const t0 = Date.now();
    setBusySec(0);
    const id = setInterval(() => setBusySec(Math.floor((Date.now() - t0) / 1000)), 1000);
    return () => clearInterval(id);
  }, [busy]);

  useEffect(() => {
    if (phase === "connected" && !sasOk) setShowSettings(false);
  }, [phase, sasOk]);

  useEffect(() => {
    if (!error) return;
    if (modalOpen || !(phase === "idle" && joinCode.trim())) {
      errorRef.current?.focus();
      return;
    }
    document.getElementById("join-code")?.focus();
  }, [error, phase, joinCode, modalOpen]);

  useEffect(() => {
    if (!pendingTransfer) return;
    const t0 = Date.now();
    setPendingLeft(DECISION_SECS);
    const id = setInterval(() => {
      setPendingLeft(Math.max(0, DECISION_SECS - Math.floor((Date.now() - t0) / 1000)));
    }, 1000);
    return () => clearInterval(id);
  }, [pendingTransfer]);

  useEffect(() => {
    if (!transfer || transfer.direction !== "sending" || xferLive || transferDone) return;
    const t0 = Date.now();
    setAcceptLeft(DECISION_SECS);
    const id = setInterval(() => {
      setAcceptLeft(Math.max(0, DECISION_SECS - Math.floor((Date.now() - t0) / 1000)));
    }, 1000);
    return () => clearInterval(id);
  }, [transfer, xferLive, transferDone]);

  useEffect(() => {
    if (!transfer || transferDone || !xferLive) {
      setXferStalled(false);
      return;
    }
    const id = setInterval(() => {
      setXferStalled(performance.now() - progressAt.current >= 15_000);
    }, 1000);
    return () => clearInterval(id);
  }, [transfer, transferDone, xferLive]);

  return (
    <div className="relative h-full w-full overflow-hidden text-[var(--text-body)]">
      <div className="pointer-events-none absolute inset-0 app-shell" />
      <div className="pointer-events-none absolute inset-0 app-mesh" />

      <div className="relative flex h-full flex-col" {...(modalOpen ? { inert: true } : {})}>
        {/* Header — constrained inner band for balance */}
        <header className="app-header px-5 py-3">
          <div className="mx-auto flex w-full max-w-[760px] items-center justify-between">
            <div className="flex min-w-0 items-center gap-3">
              <img src={brand} alt="Frostwall Beam"
                className="h-8 max-h-8 w-auto max-w-[180px] min-w-0 shrink object-contain self-center select-none"
                draggable={false}
                style={{ filter: "drop-shadow(0 2px 8px rgba(56,189,248,0.22))" }} />
              <span className="hidden text-[11px] font-medium uppercase tracking-[0.18em] text-subtle sm:inline">{t("chrome.secure")}</span>
            </div>
            <div className="flex shrink-0 items-center gap-2">
              <button type="button" onClick={() => setShowSettings(true)}
                disabled={phase === "connected" && !sasOk}
                title={phase === "connected" && !sasOk ? t("connected.verifyWait") : t("settings.title")}
                aria-label={t("settings.title")}
                className="frost-panel flex h-11 w-11 items-center justify-center rounded-full text-secondary transition hover:text-accent disabled:opacity-40">
                <Icon name="gear" />
              </button>
              <StatusPill phase={phase} net={net} inviteReady={!!invite} pairing={pairing} t={t} />
            </div>
          </div>
        </header>

        {/* Main — centers when short, scrolls when tall (no top clipping) */}
        <main className="flex-1 overflow-y-auto px-6 pb-6">
            <div className="mx-auto flex min-h-full w-full max-w-[600px] items-center justify-center py-4">
            <div className="w-full">
              {/* IDLE */}
              {phase === "idle" && (
                <div className="animate-fade-in space-y-6">
                  <div className="text-center">
                    <p className="mb-2 text-[11px] font-medium uppercase tracking-[0.28em] text-accent/80">{t("hero.eyebrow")}</p>
                    <h1 className="text-4xl font-semibold tracking-tight text-ice-gradient">{t("hero.title")}</h1>
                    <p className="mx-auto mt-2 max-w-[28rem] text-sm leading-relaxed text-muted">{t("hero.subtitle")}</p>
                    <div className="mt-4 flex flex-wrap justify-center gap-2">
                      {(["trust.e2e", "trust.noAccount", "trust.anyNet"] as const).map((k) => (
                        <span key={k} className="trust-chip">{t(k)}</span>
                      ))}
                    </div>
                  </div>

                  <div className="frost-panel flex rounded-2xl p-1">
                    {(["lan", "internet"] as Net[]).map((n) => (
                      <button key={n} type="button" onClick={() => {
                        setNet(n);
                        if (n === "lan") setJoinCode((c) => lanCodeFromInput(c));
                      }} aria-pressed={net === n}
                        className={`flex-1 min-h-11 rounded-xl px-4 py-2.5 text-sm font-medium transition ${
                          net === n
                            ? "bg-gradient-to-r from-sky-500/90 to-cyan-500/90 text-white shadow-lg shadow-sky-500/20"
                            : "text-muted hover:bg-[var(--hover-fill)] hover:text-secondary active:scale-[0.97]"}`}>
                        {t(`net.${n}`)}
                      </button>
                    ))}
                  </div>
                  <p className="px-1 text-center text-xs text-subtle">{t(
                    net === "internet"
                      ? (mailboxOn ? "net.hintInternetMailbox" : "net.hintInternet")
                      : "net.hintLan"
                  )}</p>

                  <div className="frost-panel flex rounded-2xl p-1">
                    {(["host", "join"] as Mode[]).map((m) => (
                      <button key={m} type="button" onClick={() => setMode(m)} aria-pressed={mode === m}
                        className={`flex-1 min-h-11 rounded-xl px-4 py-2.5 text-sm font-medium transition ${
                          mode === m
                            ? "seg-quiet text-heading"
                            : "text-muted hover:bg-[var(--hover-fill)] hover:text-secondary active:scale-[0.97]"}`}>
                        {t(`mode.${m}`)}
                      </button>
                    ))}
                  </div>

                  {mode === "host" ? (
                    <div className="frost-panel rounded-2xl p-6">
                      <p className="mb-2 text-sm font-medium text-heading">{t(net === "internet" ? "host.headingInternet" : "host.heading")}</p>
                      <p className="mb-5 text-sm leading-relaxed text-muted">{t(
                        net === "internet"
                          ? (mailboxOn ? "host.descInternetMailbox" : "host.descInternet")
                          : "host.desc"
                      )}</p>
                      {!config?.deviceName && (
                        <p className="mb-4 text-xs leading-relaxed text-subtle">{t("idle.deviceNameHint")}</p>
                      )}
                      <button type="button" onClick={startHost}
                        className="frost-glow w-full min-h-11 rounded-xl bg-gradient-to-r from-sky-400 via-sky-500 to-cyan-500 px-4 py-3.5 font-medium text-white transition enabled:hover:brightness-110 active:scale-[0.99] disabled:opacity-40">
                        {t(net === "internet" ? "host.buttonInternet" : "host.button")}
                      </button>
                    </div>
                  ) : (
                    <div className="frost-panel rounded-2xl p-6">
                      <p className="mb-2 text-sm font-medium text-heading">
                        <label htmlFor="join-code">{t(
                          net === "internet"
                            ? (mailboxOn ? "join.headingInternetMailbox" : "join.headingInternet")
                            : "join.heading"
                        )}</label>
                      </p>
                      <p className="mb-5 text-sm leading-relaxed text-muted">{t(
                        net === "internet"
                          ? (mailboxOn ? "join.descInternetMailbox" : "join.descInternet")
                          : "join.desc"
                      )}</p>
                      {!config?.deviceName && (
                        <p className="mb-4 text-xs leading-relaxed text-subtle">{t("idle.deviceNameHint")}</p>
                      )}
                      <div className="space-y-3">
                        {net === "internet" ? (
                          <textarea id="join-code" value={joinCode}
                            aria-label={t(mailboxOn ? "join.headingInternetMailbox" : "join.headingInternet")}
                            onChange={(e) => setJoinCode(e.target.value.slice(0, INVITE_PASTE_MAX))}
                            onKeyDown={(e) => {
                              if (e.key === "Enter" && !e.shiftKey) {
                                e.preventDefault();
                                startJoin();
                              }
                            }}
                            autoCapitalize="off" autoCorrect="off" spellCheck={false}
                            rows={3}
                            maxLength={INVITE_PASTE_MAX}
                            placeholder={t(mailboxOn ? "join.invitePlaceholderMailbox" : "join.invitePlaceholder")}
                            className="min-h-[5.5rem] w-full resize-y rounded-xl border border-input bg-input px-3 py-3 text-left font-mono text-[13px] leading-snug tracking-tight text-heading outline-none transition focus-visible:border-sky-400/60" />
                        ) : (
                        <input id="join-code" value={joinCode}
                          aria-label={t("join.heading")}
                          onChange={(e) => {
                            const raw = e.target.value;
                            if (looksLikeInvite(raw)) {
                              setNet("internet");
                              setJoinCode(raw.slice(0, INVITE_PASTE_MAX));
                              return;
                            }
                            setJoinCode(lanCodeFromInput(raw).slice(0, 6));
                          }}
                          onKeyDown={(e) => e.key === "Enter" && startJoin()}
                          inputMode="numeric"
                          autoCapitalize="off" autoCorrect="off" spellCheck={false}
                          placeholder="••••••"
                          className="font-mono-num w-full rounded-xl border border-input bg-input px-4 py-3.5 text-center text-2xl tracking-[0.45em] text-heading outline-none transition focus-visible:border-sky-400/60" />
                        )}
                        <button type="button" onClick={() => { void pasteJoin(); }}
                          className="w-full min-h-11 rounded-xl border border-sky-300/15 bg-[var(--hover-fill)] px-4 py-2.5 text-sm font-medium text-accent-strong transition hover:bg-sky-400/10 active:scale-[0.99]">
                          {t("join.pasteClipboard")}
                        </button>
                        <button type="button" onClick={startJoin} disabled={net === "lan" ? lanCodeFromInput(joinCode).length !== 6 : !joinCode.trim()}
                          className="frost-glow w-full min-h-11 rounded-xl bg-gradient-to-r from-sky-400 via-sky-500 to-cyan-500 px-6 py-3.5 font-medium text-white transition enabled:hover:brightness-110 active:scale-[0.99]">
                          {t("join.button")}
                        </button>
                      </div>
                    </div>
                  )}
                  <Footer t={t} />
                </div>
              )}

              {/* WAITING */}
              {busy && !(peerChoices && peerChoices.length > 1) && (
                <div className="animate-fade-in frost-panel relative overflow-hidden rounded-2xl p-8">
                  {phase === "hosting" && !pairing ? (
                    net === "internet" ? (
                      <div className="flex flex-col items-center gap-1.5 text-center">
                        <p className="text-xs font-medium uppercase tracking-[0.25em] text-accent/80">{t("waiting.inviteLabel")}</p>
                        <div className="invite-block mt-3 w-full rounded-2xl border border-sky-300/15 bg-[var(--hover-fill)] px-4 py-4 text-heading" aria-busy={!invite}>
                          {invite || (busySec > 0
                            ? t("waiting.invitePreparingElapsed").replace("{n}", String(busySec))
                            : t("waiting.invitePreparing"))}
                        </div>
                        <button type="button" onClick={copyInvite} disabled={!invite}
                          aria-live="polite"
                          className="frost-glow mt-3 w-full min-h-11 rounded-xl bg-gradient-to-r from-sky-400 via-sky-500 to-cyan-500 px-4 py-2.5 text-sm font-medium text-white transition enabled:hover:brightness-110 active:scale-[0.99] disabled:opacity-40">
                          {copied ? t("waiting.copied") : t("waiting.copyButton")}
                        </button>
                        <p className="mt-2 text-xs text-muted">{t("waiting.inviteHint")}</p>
                        <p className="mt-1 text-xs text-subtle">{t("waiting.inviteSecret")}</p>
                        {inviteMailboxOk && code && (
                          <button type="button" onClick={() => {
                            void copyText(code).then((ok) => {
                              if (ok) pushToast("ok", t("waiting.copied"));
                              else pushToast("err", t("toast.copyFailed"));
                            });
                          }}
                            title={t("waiting.copyHint")}
                            className="mt-4 font-mono-num text-sm text-secondary transition hover:text-heading">
                            {t("waiting.codeAlso")}: <span className="text-heading tracking-[0.2em]">{code}</span>
                          </button>
                        )}
                        {mailboxOn && invite && !inviteMailboxOk && (
                          <p className="mt-3 text-xs text-warn">{t("waiting.mailboxSkip")}</p>
                        )}
                        <p className="mt-6 text-sm text-muted">{t(
                          inviteMailboxOk ? "waiting.hostWaitInternetMailbox" : "waiting.hostWaitInternet"
                        )}{busySec > 0 ? ` · ${busySec}s` : ""}</p>
                        {invite && !inviteHasRelay && (
                          <p className="mt-3 text-xs text-warn">{t(
                            relayHuntStarted.current != null && Date.now() - relayHuntStarted.current < 25_000
                              ? "waiting.relayHunting"
                              : "waiting.noRelay"
                          )}</p>
                        )}
                      </div>
                    ) : (
                      <div className="flex flex-col items-center gap-1.5 text-center">
                        <p className="text-xs font-medium uppercase tracking-[0.25em] text-accent/80">{t("waiting.codeLabel")}</p>
                        <button type="button" onClick={copyInvite} disabled={!code} title={t("waiting.copyHint")} aria-label={t("waiting.copyHint")}
                          className="font-mono-num group relative mt-3 min-h-11 rounded-2xl text-6xl font-semibold tracking-[0.3em] text-heading transition hover:scale-[1.02] active:scale-[0.98]">
                          {code || "••••••"}
                          <span className="absolute -inset-4 -z-10 rounded-3xl bg-sky-400/10 blur-2xl transition group-hover:bg-sky-400/20" />
                        </button>
                        <div className="mt-2 text-xs text-muted" aria-live="polite">
                          {copied ? <span className="text-accent">{t("waiting.copied")}</span> : t("waiting.copyHint")}
                        </div>
                        <p className="mt-6 text-sm text-muted">{t("waiting.hostWait")}{busySec > 0 ? ` · ${busySec}s` : ""}</p>
                      </div>
                    )
                  ) : (
                    <div className="flex flex-col items-center gap-5 text-center">
                      <div className="relative flex h-16 w-16 items-center justify-center">
                        <span className="absolute inline-flex h-12 w-12 rounded-full bg-sky-400/20 animate-radar" />
                        <span className="absolute inline-flex h-12 w-12 rounded-full bg-cyan-400/10 animate-radar [animation-delay:0.8s]" />
                        <span className="relative h-10 w-10 rounded-full bg-gradient-to-br from-sky-400 to-cyan-500" />
                      </div>
                      <p className="text-sm text-muted">
                        {t(
                          pairing
                            ? "waiting.pairing"
                            : net === "internet"
                              ? (mailboxOn && /^\d{6}$/.test(joinCode.replace(/\s/g, ""))
                                ? "join.waitingInternetCode"
                                : "join.waitingInternet")
                              : (joinDial ? "join.waitingLan" : "join.scanningPeers")
                        )}
                        {busySec > 0 ? ` · ${busySec}s` : ""}
                      </p>
                      {!pairing && net === "internet" && busySec >= 25 && (
                        <p className="max-w-[22rem] text-xs leading-relaxed text-subtle">{t("join.waitingSlow")}</p>
                      )}
                    </div>
                  )}
                  <div className="mt-7 flex justify-center">
                    <button type="button" onClick={() => { void doDisconnect(); }}
                      className="min-h-11 rounded-lg px-4 py-2.5 text-sm text-muted transition hover:bg-[var(--hover-fill)] hover:text-secondary active:scale-[0.98]">
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
                      <div className="flex items-center gap-2 text-xs font-medium uppercase tracking-[0.2em] text-ok">
                        <span className="relative flex h-2 w-2">
                          <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400 opacity-70" />
                          <span className="relative inline-flex h-2 w-2 rounded-full bg-emerald-400" />
                        </span>
                        {t("connected.secure")}
                      </div>
                      <span className="text-xs text-muted">{t("connected.rotates").replace("{n}", String(secLeft))}</span>
                    </div>
                    <div className="mt-4 min-w-0 break-all font-mono-num text-4xl font-semibold tracking-[0.35em] text-heading">{liveness || "••••••"}</div>
                    <div className="mt-4 h-1 w-full overflow-hidden rounded-full bg-[var(--hover-fill)]">
                      <div className="h-full rounded-full bg-gradient-to-r from-sky-400 to-cyan-400 transition-[width] duration-1000 ease-linear"
                        style={{ width: `${(secLeft / STEP) * 100}%` }} />
                    </div>
                    <p className="mt-3 text-xs text-muted">{t("connected.codeHint")}</p>
                    <div className="mt-4 space-y-1 border-t border-sky-300/10 pt-3 text-xs text-muted">
                        {localName && <p>{t("connected.you").replace("{name}", localName)}</p>}
                        <p>{peerName
                          ? t("connected.peer").replace("{name}", peerName)
                          : t("connected.peerGeneric")}</p>
                      </div>
                    {!sasOk && (
                      <div className="mt-5 border-t border-sky-300/10 pt-4 text-left">
                        <p className="text-sm font-medium text-heading">{t("connected.verifyTitle")}</p>
                        <p className="mt-1 text-xs leading-relaxed text-muted">{t("connected.verifyHint")}</p>
                        {pendingTransfer && (
                          <p className="mt-2 text-xs leading-relaxed text-warn">
                            {t("connected.verifyIncoming")}{" "}
                            {t("transfer.pending.expires").replace("{n}", String(pendingLeft))}
                          </p>
                        )}
                        <div className="mt-3 flex gap-2">
                          <button type="button" disabled={liveness.length !== 6} onClick={() => setSasOk(true)}
                            className="frost-glow min-h-11 flex-1 rounded-xl bg-gradient-to-r from-sky-400 via-sky-500 to-cyan-500 px-3 py-2.5 text-sm font-medium text-white transition hover:brightness-110 active:scale-[0.99] disabled:opacity-40">
                            {t("connected.verifyYes")}
                          </button>
                          <button type="button" onClick={() => {
                            pushToast("err", t("toast.sasMismatch"));
                            void doDisconnect();
                          }}
                            className="min-h-11 flex-1 rounded-xl border border-sky-300/15 bg-[var(--hover-fill)] px-3 py-2.5 text-sm font-medium text-secondary transition hover:text-danger active:scale-[0.99]">
                            {t("connected.verifyNo")}
                          </button>
                        </div>
                      </div>
                    )}
                  </div>

                  {transfer ? (
                    <TransferCard transfer={transfer} progress={progress} pct={pct} speed={speed} eta={eta}
                      done={transferDone} accepted={xferLive} acceptLeft={acceptLeft} stalled={xferStalled}
                      t={t} onCancel={cancelTransfer} />
                  ) : sendPrep || recvPrep ? (
                    <div className="frost-panel flex flex-col items-center gap-4 rounded-2xl p-8 text-center">
                      <div className="relative flex h-16 w-16 items-center justify-center">
                        <span className="absolute inline-flex h-12 w-12 rounded-full bg-sky-400/20 animate-radar" />
                        <span className="absolute inline-flex h-12 w-12 rounded-full bg-cyan-400/10 animate-radar [animation-delay:0.8s]" />
                        <span className="relative h-10 w-10 rounded-full bg-gradient-to-br from-sky-400 to-cyan-500" />
                      </div>
                      <p className="text-sm text-secondary">{t(sendPrep ? "transfer.preparing" : "transfer.recvStarting")}</p>
                      {sendPrep && (
                      <button type="button" onClick={cancelTransfer}
                        className="min-h-11 rounded-xl border border-sky-300/15 bg-[var(--hover-fill)] px-4 py-2.5 text-sm font-medium text-danger transition hover:text-danger active:scale-[0.99]">
                        {t("transfer.cancel")}
                      </button>
                      )}
                    </div>
                  ) : !sasOk ? (
                    <div className="frost-panel rounded-2xl p-8 text-center text-sm text-muted">
                      <p>{t(pendingTransfer ? "connected.verifyIncoming" : "connected.verifyWait")}</p>
                      {pendingTransfer && (
                        <>
                          <IncomingPreview transfer={pendingTransfer} t={t} />
                          <p className="mt-3 max-w-full truncate text-xs text-muted" title={saveDirLabel}>↧ {saveDirLabel}</p>
                          <div className="mt-3 flex gap-2">
                            <button type="button" onClick={() => { void chooseSaveDir().catch((e) => showError(String(e))); }}
                              className="min-h-11 flex-1 rounded-xl border border-sky-300/15 bg-[var(--hover-fill)] px-4 py-2.5 text-sm font-medium text-accent-strong transition hover:bg-[var(--hover-fill)] active:scale-[0.99]">
                              {t("settings.saveDirChoose")}
                            </button>
                            <button type="button" onClick={() => void respondPending(false)}
                              className="min-h-11 flex-1 rounded-xl border border-rose-300/20 bg-rose-500/10 px-4 py-2.5 text-sm font-medium text-danger transition hover:bg-rose-500/20 active:scale-[0.99]">
                              {t("transfer.pending.reject")}
                            </button>
                          </div>
                        </>
                      )}
                    </div>
                  ) : (
                    <div role="region" aria-label={t("drop.hint")}
                      className={`relative flex flex-col items-center justify-center rounded-2xl border-2 border-dashed p-10 text-center transition ${
                        dragging ? "border-sky-400/70 bg-sky-400/10" : "border-[color:var(--panel-border)] bg-[var(--hover-fill)]"}`}>
                      <div className="mb-3 flex h-12 w-12 items-center justify-center rounded-xl bg-sky-400/10">
                        <Icon name="upload" className="text-accent" />
                      </div>
                      <p className="text-sm text-secondary">{t("drop.hint")}</p>
                      <p className="mb-4 mt-0.5 text-xs text-subtle">{t("drop.or")}</p>
                      <div className="flex gap-2">
                        <button type="button" onClick={pickFiles}
                          className="frost-glow min-h-11 rounded-xl bg-gradient-to-r from-sky-400 via-sky-500 to-cyan-500 px-4 py-2.5 text-sm font-medium text-white transition hover:brightness-110 active:scale-[0.98]">
                          {t("drop.files")}
                        </button>
                        <button type="button" onClick={pickFolder}
                          className="min-h-11 rounded-xl border border-sky-300/15 bg-[var(--hover-fill)] px-4 py-2.5 text-sm font-medium text-accent-strong transition hover:bg-[var(--hover-fill)] active:scale-[0.98]">
                          {t("drop.folder")}
                        </button>
                      </div>
                      <p className="mt-5 max-w-full truncate text-xs text-muted" title={saveDirLabel}>↧ {saveDirLabel}</p>
                    </div>
                  )}

                  <button type="button" onClick={requestDisconnect}
                    className="w-full min-h-11 rounded-xl border border-sky-300/15 bg-[var(--hover-fill)] px-4 py-3 text-sm font-medium text-secondary transition hover:bg-[var(--hover-fill)] hover:text-danger active:scale-[0.99]">
                    {t("btn.disconnect")}
                  </button>
                </div>
              )}
            </div>
          </div>
        </main>
      </div>

      {error && (
        <div className="pointer-events-none absolute inset-x-0 top-16 z-[70] flex justify-center px-6">
          <div ref={errorRef} role="alert" aria-live="assertive" tabIndex={-1}
            className="animate-fade-in pointer-events-auto flex w-full max-w-[600px] items-start gap-2 rounded-xl border border-rose-400/25 bg-rose-500/15 px-4 py-3 text-sm text-danger shadow-2xl backdrop-blur-md">
            <Icon name="alert" className="mt-0.5 shrink-0 text-danger" />
            <span className="min-w-0 flex-1">{error}</span>
            <button type="button" onClick={() => setError(null)} aria-label={t("common.dismiss")}
              className="flex h-11 w-11 shrink-0 items-center justify-center rounded-lg text-danger transition hover:bg-rose-500/20">
              <Icon name="close" />
            </button>
          </div>
        </div>
      )}

      {disconnectAsk && (
        <DisconnectConfirmModal t={t}
          onYes={() => { void doDisconnect(); }}
          onNo={() => setDisconnectAsk(false)} />
      )}

      {peerChoices && peerChoices.length > 1 && (
        <PeerPickerModal peers={peerChoices} t={t}
          onPick={connectToPeer} onCancel={() => { void doDisconnect(); }} />
      )}

      {pendingTransfer && sasOk && (
        <PendingTransferModal transfer={pendingTransfer} t={t} formatBytes={formatBytes}
          leftSec={pendingLeft}
          saveDirLabel={saveDirLabel}
          onChooseSaveDir={() => chooseSaveDir().catch((e) => showError(String(e)))}
          onAccept={() => respondPending(true)} onReject={() => respondPending(false)} />
      )}

      {showSettings && (
        <SettingsModal t={t} lang={lang} setLang={setLang} theme={theme} setTheme={setTheme}
          config={config} saveDirLabel={saveDirLabel} history={history} mailboxOn={mailboxOn}
          formatBytes={formatBytes}
          identityLocked={phase !== "idle"}
          saveDirLocked={!!(transfer || sendPrep || recvPrep || xferLive)}
          onChooseSaveDir={chooseSaveDir} onClose={() => setShowSettings(false)}
          onSaved={refreshConfig}
          onMailboxSaved={(cleared) => pushToast("ok", t(cleared ? "toast.mailboxUrlCleared" : "toast.mailboxUrlSaved"))} />
      )}

      {/* toasts */}
      <div aria-live="polite" className="pointer-events-none absolute bottom-5 left-1/2 z-[80] flex max-h-[50vh] -translate-x-1/2 flex-col items-center gap-2 overflow-y-auto">
        {toasts.map((to) => (
          <div key={to.id}
            className={`animate-fade-in pointer-events-auto flex items-center gap-2 rounded-xl border px-4 py-2.5 text-sm shadow-2xl backdrop-blur-md ${
              to.kind === "ok" ? "border-emerald-400/25 bg-emerald-500/15 text-ok"
              : to.kind === "err" ? "border-rose-400/25 bg-rose-500/15 text-danger"
              : "border-sky-300/20 bg-sky-500/15 text-accent-strong"}`}>
            <Icon name={to.kind === "ok" ? "check" : to.kind === "err" ? "alert" : "info"} className="shrink-0 opacity-90" />
            {to.msg}
          </div>
        ))}
      </div>
    </div>
  );
}

/* ---------- sub-components ---------- */

function StatusPill({ phase, net, inviteReady, pairing, t }: {
  phase: Phase; net: Net; inviteReady: boolean; pairing: boolean; t: (k: string) => string
}) {
  let key = "status.offline";
  let dot = "bg-slate-500";
  let text = "text-muted";
  if (phase === "connected") {
    key = "status.encrypted";
    dot = "bg-emerald-400";
    text = "text-ok";
  } else if (phase === "joining" || pairing) {
    key = "status.connecting";
    dot = "bg-amber-400";
    text = "text-warn";
  } else if (phase === "hosting") {
    key = net === "internet"
      ? (inviteReady ? "status.hostingInternet" : "status.hostingInternetWait")
      : "status.hosting";
    dot = "bg-amber-400";
    text = "text-warn";
  }
  return (
    <div className="frost-panel flex h-8 items-center gap-2 rounded-full px-3 text-xs font-medium">
      <span className={`h-1.5 w-1.5 rounded-full ${dot}`} />
      <span className={text}>{t(key)}</span>
    </div>
  );
}

function TransferCard({ transfer, progress, pct, speed, eta, done, accepted, acceptLeft, stalled, t, onCancel }: {
  transfer: TransferStart; progress: Progress | null; pct: number; speed: number; eta: number; done: boolean;
  accepted: boolean; acceptLeft: number; stalled: boolean;
  t: (k: string) => string; onCancel: () => void;
}) {
  const sending = transfer.direction === "sending";
  const transferred = progress?.transferred ?? 0;
  const awaitingAccept = sending && !done && !accepted;
  const fileWord = transfer.file_count === 1 ? t("transfer.fileOne") : t("transfer.fileMany");
  const title = done
    ? t("transfer.completed")
    : awaitingAccept
      ? t("transfer.awaitingAccept")
      : t(`transfer.${sending ? "sending" : "receiving"}`);
  return (
    <div className="frost-panel rounded-2xl p-6">
      <div className="mb-3 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <span className={`flex h-7 w-7 items-center justify-center rounded-lg ${sending ? "bg-sky-400/15 text-accent" : "bg-cyan-400/15 text-accent"}`}>
            <Icon name={sending ? "upload" : "download"} />
          </span>
          <span className="text-sm font-medium text-heading">{title}</span>
          <span className="text-xs text-muted">· {transfer.file_count} {fileWord}</span>
        </div>
        <span className="font-mono-num text-sm text-secondary">{awaitingAccept ? "—" : `${pct.toFixed(0)}%`}</span>
      </div>

      <div className="mb-4 max-h-32 space-y-1 overflow-auto pr-1">
        {transfer.items.map((it, i) => (
          <div key={i} className="flex items-center justify-between rounded-lg bg-[var(--hover-fill)] px-3 py-1.5">
            <div className="flex min-w-0 items-center gap-2">
              <Icon name={it.name.endsWith("/") ? "folder" : "file"} className="shrink-0 text-subtle" />
              <span className="truncate text-xs text-secondary">{it.name}</span>
            </div>
            <span className="ml-2 shrink-0 font-mono-num text-xs text-muted">{formatBytes(it.size)}</span>
          </div>
        ))}
        {transfer.file_count > transfer.items.length && (
          <p className="px-1 text-xs text-muted">+{transfer.file_count - transfer.items.length}</p>
        )}
      </div>
      {awaitingAccept && (
        <p className="mb-3 text-xs text-muted" role="timer">
          {t("transfer.awaitingAcceptLeft").replace("{n}", String(acceptLeft))}
        </p>
      )}
      {!awaitingAccept && !done && stalled && (
        <p className="mb-3 text-xs text-warn">{t("transfer.stalled")}</p>
      )}

      <div className="h-2 w-full overflow-hidden rounded-full bg-[var(--hover-fill)]">
        <div className={`h-full rounded-full transition-[width] duration-200 ${done ? "bg-gradient-to-r from-emerald-400 to-teal-400" : "bg-gradient-to-r from-sky-400 to-cyan-400"}`}
          style={{ width: `${Math.min(100, pct)}%` }} />
      </div>
      <div className="mt-2 flex justify-between text-xs text-muted">
        <span className="font-mono-num">{formatBytes(transferred)} / {formatBytes(transfer.total)}</span>
        <span className="font-mono-num">
          {!done && speed > 0 ? `${formatBytes(speed)}${t("transfer.perSecSuffix")}` : ""}
          {!done && eta > 0 ? ` · ${eta}${t("transfer.leftSuffix")}` : ""}
          {done ? t("transfer.verified") : ""}
        </span>
      </div>
      {!done && (
        <button type="button" onClick={onCancel}
          className="mt-4 w-full min-h-11 rounded-xl border border-rose-300/20 bg-rose-500/10 px-4 py-2.5 text-sm font-medium text-danger transition hover:bg-rose-500/20 active:scale-[0.99]">
          {t("transfer.cancel")}
        </button>
      )}
    </div>
  );
}

function Footer({ t }: { t: (k: string) => string }) {
  return (
    <div className="flex flex-col items-center gap-1.5 text-xs text-muted">
      <div className="flex items-center justify-center gap-2">
        <Icon name="lock" />
        <span>{t("footer.crypto")}</span>
      </div>
      <span className="text-subtle">{t("footer.local")}</span>
    </div>
  );
}

function SettingsModal({ t, lang, setLang, theme, setTheme, config, saveDirLabel, history, mailboxOn, formatBytes, identityLocked, saveDirLocked, onChooseSaveDir, onClose, onSaved, onMailboxSaved }: {
  t: (k: string) => string;
  lang: Lang; setLang: (l: Lang) => void;
  theme: Theme; setTheme: (t: Theme) => void;
  config: AppConfig | null; saveDirLabel: string;
  history: TransferRecord[];
  mailboxOn: boolean;
  formatBytes: (n: number) => string;
  identityLocked: boolean;
  saveDirLocked: boolean;
  onChooseSaveDir: () => Promise<void>; onClose: () => void;
  onSaved: () => Promise<void>;
  onMailboxSaved: (cleared: boolean) => void;
}) {
  const [name, setName] = useState(config?.deviceName ?? "");
  const [mailboxUrl, setMailboxUrl] = useState(config?.mailboxUrl ?? "");
  const [mailboxClearAsk, setMailboxClearAsk] = useState(false);
  const [formErr, setFormErr] = useState<string | null>(null);
  const panelRef = useRef<HTMLDivElement>(null);
  useFocusTrap(true, panelRef);

  useEffect(() => {
    setName(config?.deviceName ?? "");
  }, [config?.deviceName]);

  useEffect(() => {
    setMailboxUrl(config?.mailboxUrl ?? "");
    setMailboxClearAsk(false);
  }, [config?.mailboxUrl]);

  useEffect(() => {
    const h = (e: KeyboardEvent) => { if (e.key === "Escape") onClose(); };
    window.addEventListener("keydown", h);
    return () => window.removeEventListener("keydown", h);
  }, [onClose]);

  const fail = (e: unknown) => setFormErr(translateError(String(e), t));

  const saveMailbox = async () => {
    if (identityLocked) return;
    const trimmed = mailboxUrl.trim();
    if (!trimmed && (config?.mailboxUrl ?? "").trim() && !mailboxClearAsk) {
      setMailboxClearAsk(true);
      return;
    }
    setMailboxClearAsk(false);
    setFormErr(null);
    try { await invoke("set_mailbox_url", { url: trimmed }); await onSaved(); onMailboxSaved(!trimmed); }
    catch (e) { fail(e); }
  };

  const saveName = async () => {
    if (identityLocked || !name.trim()) return;
    setFormErr(null);
    try { await invoke("set_device_name", { name: name.trim() }); await onSaved(); onClose(); }
    catch (e) { fail(e); }
  };

  return (
    <div role="dialog" aria-modal="true" aria-labelledby="settings-title"
      className="absolute inset-0 z-50 flex items-center justify-center overflow-y-auto bg-black/60 p-6 backdrop-blur-sm" onClick={onClose}>
      <div ref={panelRef} className="frost-panel animate-fade-in my-auto w-full max-w-md max-h-full overflow-y-auto rounded-2xl p-6" onClick={(e) => e.stopPropagation()}>
        <div className="mb-5 flex items-center justify-between">
          <h2 id="settings-title" className="text-xl font-semibold text-heading">{t("settings.title")}</h2>
          <button type="button" onClick={onClose} aria-label={t("common.dismiss")}
            className="flex h-11 w-11 items-center justify-center rounded-lg text-muted transition hover:bg-[var(--hover-fill)] hover:text-secondary active:scale-95">
            <Icon name="close" />
          </button>
        </div>
        {formErr && (
          <div role="alert" className="mb-4 flex items-start gap-2 rounded-xl border border-rose-400/25 bg-rose-500/10 px-3 py-2.5 text-sm text-danger">
            <Icon name="alert" className="mt-0.5 shrink-0 text-danger" />
            <span className="min-w-0 flex-1">{formErr}</span>
          </div>
        )}

        <div className="space-y-5">
          <div>
            <label className="mb-2 block text-xs font-medium uppercase tracking-wider text-muted">{t("settings.theme")}</label>
            <div className="frost-panel flex rounded-xl p-1">
              {(["system", "dark", "light"] as Theme[]).map((th) => (
                <button type="button" key={th} onClick={() => setTheme(th)}
                  className={`flex-1 min-h-11 rounded-lg px-3 py-2 text-sm font-medium transition ${
                    theme === th ? "bg-gradient-to-r from-sky-500/90 to-cyan-500/90 text-white" : "text-muted hover:bg-[var(--hover-fill)] hover:text-secondary active:scale-[0.97]"}`}>
                  {t(`settings.theme.${th}`)}
                </button>
              ))}
            </div>
          </div>

          <div>
            <label className="mb-2 block text-xs font-medium uppercase tracking-wider text-muted">{t("settings.language")}</label>
            <div className="frost-panel flex rounded-xl p-1">
              {(["tr", "en"] as Lang[]).map((l) => (
                <button type="button" key={l} onClick={() => setLang(l)}
                  className={`flex-1 min-h-11 rounded-lg px-4 py-2 text-sm font-medium transition ${
                    lang === l ? "bg-gradient-to-r from-sky-500/90 to-cyan-500/90 text-white" : "text-muted hover:bg-[var(--hover-fill)] hover:text-secondary active:scale-[0.97]"}`}>
                  {l === "tr" ? "Türkçe" : "English"}
                </button>
              ))}
            </div>
          </div>

          <div>
            <label className="mb-2 block text-xs font-medium uppercase tracking-wider text-muted">{t("settings.saveDir")}</label>
            <div className="flex items-center gap-2">
              <div title={saveDirLabel} className="font-mono-num min-w-0 flex-1 break-all rounded-xl border border-input bg-input px-3 py-2.5 text-sm text-secondary">{saveDirLabel}</div>
              <button type="button" onClick={() => { setFormErr(null); void onChooseSaveDir().catch(fail); }}
                disabled={saveDirLocked}
                className="shrink-0 min-h-11 rounded-xl bg-sky-400/15 px-4 py-2.5 text-sm font-medium text-accent-strong transition enabled:hover:bg-sky-400/25 active:scale-[0.98] disabled:opacity-40">
                {t("settings.saveDirChoose")}
              </button>
            </div>
            {saveDirLocked && (
              <p className="mt-2 text-xs leading-relaxed text-warn">{t("settings.saveDirLocked")}</p>
            )}
          </div>

          <div>
            <label htmlFor="device-name" className="mb-2 block text-xs font-medium uppercase tracking-wider text-muted">{t("settings.deviceName")}</label>
            <div className="flex gap-2">
              <input id="device-name" value={name} aria-label={t("settings.deviceName")}
                maxLength={48}
                disabled={identityLocked}
                onChange={(e) => setName(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && saveName()}
                placeholder={t("settings.deviceNamePlaceholder")}
                className="min-w-0 flex-1 rounded-xl border border-input bg-input px-3 py-2.5 text-sm text-heading outline-none transition focus-visible:border-sky-400/60 disabled:opacity-40" />
              <button type="button" onClick={saveName} disabled={identityLocked || !name.trim()}
                className="shrink-0 min-h-11 rounded-xl bg-sky-400/15 px-4 py-2.5 text-sm font-medium text-accent-strong transition enabled:hover:bg-sky-400/25 active:scale-[0.98] disabled:opacity-40">
                {t("settings.deviceNameSave")}
              </button>
            </div>
          </div>

          <div>
            <label htmlFor="mailbox-url" className="mb-2 block text-xs font-medium uppercase tracking-wider text-muted">{t("settings.mailboxUrl")}</label>
            <div className="flex gap-2">
              <input id="mailbox-url" value={mailboxUrl} aria-label={t("settings.mailboxUrl")}
                disabled={identityLocked}
                onChange={(e) => { setMailboxUrl(e.target.value); setMailboxClearAsk(false); }}
                onKeyDown={(e) => e.key === "Enter" && void saveMailbox()}
                placeholder={t("settings.mailboxUrlPlaceholder")}
                className="min-w-0 flex-1 rounded-xl border border-input bg-input px-3 py-2.5 text-sm text-heading outline-none transition focus-visible:border-sky-400/60 disabled:opacity-40" />
              <button type="button" onClick={() => void saveMailbox()} disabled={identityLocked}
                className="shrink-0 min-h-11 rounded-xl bg-sky-400/15 px-4 py-2.5 text-sm font-medium text-accent-strong transition enabled:hover:bg-sky-400/25 active:scale-[0.98] disabled:opacity-40">
                {t("settings.mailboxUrlSave")}
              </button>
            </div>
            {mailboxClearAsk && (
              <div className="mt-2 rounded-xl border border-amber-400/25 bg-amber-500/10 px-3 py-3">
                <p className="text-xs leading-relaxed text-warn">{t("settings.mailboxClearConfirm")}</p>
                <div className="mt-2 flex gap-2">
                  <button type="button" onClick={() => void saveMailbox()}
                    className="min-h-11 flex-1 rounded-xl bg-rose-500/15 px-3 py-2 text-sm font-medium text-danger transition hover:bg-rose-500/25">
                    {t("settings.mailboxClearYes")}
                  </button>
                  <button type="button" onClick={() => setMailboxClearAsk(false)}
                    className="min-h-11 flex-1 rounded-xl border border-sky-300/15 px-3 py-2 text-sm text-muted transition hover:text-secondary">
                    {t("common.cancel")}
                  </button>
                </div>
              </div>
            )}
            <p className="mt-2 text-xs leading-relaxed text-muted">{t("settings.mailboxUrlHint")}</p>
            <p className="mt-1 text-xs text-subtle">{t(mailboxOn ? "settings.mailboxOn" : "settings.mailboxOff")}</p>
            {identityLocked && (
              <p className="mt-2 text-xs leading-relaxed text-warn">{t("settings.identityLocked")}</p>
            )}
          </div>

          <div>
            <label className="mb-2 block text-xs font-medium uppercase tracking-wider text-muted">{t("settings.history")}</label>
            {history.length === 0 ? (
              <p className="text-sm text-subtle">{t("settings.historyEmpty")}</p>
            ) : (
              <ul className="max-h-48 space-y-1 overflow-auto text-xs text-muted">
                {history.map((h) => {
                  const rel = relativeTime(h.at, t);
                  return (
                  <li key={h.id} className="rounded-lg bg-[var(--hover-fill)] px-3 py-2">
                    {rel ? <>{rel}{" · "}</> : null}
                    {new Date(h.at).toLocaleString(lang === "tr" ? "tr-TR" : "en-GB", {
                      day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit",
                    })}
                    {" · "}
                    {t(h.fileCount === 1 ? "settings.historyEntryOne" : "settings.historyEntry")
                      .replace("{dir}", h.direction === "sending" ? "↑" : "↓")
                      .replace("{n}", String(h.fileCount))
                      .replace("{size}", formatBytes(h.totalBytes))}
                    {" · "}{h.ok ? t("settings.historyOk") : h.err ? translateError(h.err, t) : t("settings.historyFail")}
                  </li>
                  );
                })}
              </ul>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

function DisconnectConfirmModal({ t, onYes, onNo }: {
  t: (k: string) => string;
  onYes: () => void;
  onNo: () => void;
}) {
  const panelRef = useRef<HTMLDivElement>(null);
  useFocusTrap(true, panelRef);
  useEffect(() => {
    const h = (e: KeyboardEvent) => { if (e.key === "Escape") onNo(); };
    window.addEventListener("keydown", h);
    return () => window.removeEventListener("keydown", h);
  }, [onNo]);
  return (
    <div role="dialog" aria-modal="true" aria-labelledby="disconnect-title"
      className="absolute inset-0 z-[75] flex items-center justify-center overflow-y-auto bg-black/70 p-6 backdrop-blur-sm" onClick={onNo}>
      <div ref={panelRef} className="frost-panel animate-fade-in my-auto w-full max-w-md rounded-2xl p-6" onClick={(e) => e.stopPropagation()}>
        <h2 id="disconnect-title" className="text-xl font-semibold text-heading">{t("disconnect.confirmTitle")}</h2>
        <p className="mt-2 text-sm leading-relaxed text-muted">{t("disconnect.confirmTransfer")}</p>
        <div className="mt-5 flex gap-2">
          <button type="button" onClick={onNo}
            className="min-h-11 flex-1 rounded-xl border border-sky-300/15 px-4 py-2.5 text-sm font-medium text-muted transition hover:text-secondary">
            {t("common.cancel")}
          </button>
          <button type="button" onClick={onYes}
            className="min-h-11 flex-1 rounded-xl border border-rose-300/20 bg-rose-500/15 px-4 py-2.5 text-sm font-medium text-danger transition hover:bg-rose-500/25">
            {t("disconnect.confirmYes")}
          </button>
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
  const panelRef = useRef<HTMLDivElement>(null);
  useFocusTrap(true, panelRef);

  useEffect(() => {
    const h = (e: KeyboardEvent) => { if (e.key === "Escape") onCancel(); };
    window.addEventListener("keydown", h);
    return () => window.removeEventListener("keydown", h);
  }, [onCancel]);

  return (
    <div role="dialog" aria-modal="true" aria-labelledby="peer-picker-title"
      className="absolute inset-0 z-[55] flex items-center justify-center overflow-y-auto bg-black/70 p-6 backdrop-blur-sm" onClick={onCancel}>
      <div ref={panelRef} className="frost-panel animate-fade-in my-auto w-full max-w-md rounded-2xl p-6" onClick={(e) => e.stopPropagation()}>
        <h2 id="peer-picker-title" className="text-xl font-semibold text-heading">{t("join.pickPeer")}</h2>
        <p className="mt-2 text-sm text-muted">{t("join.pickPeerDesc")}</p>
        <ul className="mt-4 space-y-2">
          {peers.map((p) => (
            <li key={peerEndpoint(p)}>
              <button type="button" onClick={() => onPick(p)}
                className="w-full min-h-11 rounded-xl border border-sky-300/15 bg-[var(--hover-fill)] px-4 py-3 text-left transition hover:bg-[var(--hover-fill)] active:scale-[0.99]">
                <span className="block text-sm font-medium text-heading">{p.displayName}</span>
                <span className="font-mono-num text-xs text-subtle">{peerEndpoint(p)}</span>
              </button>
            </li>
          ))}
        </ul>
        <button type="button" onClick={onCancel}
          className="mt-4 w-full min-h-11 rounded-xl px-4 py-2.5 text-sm text-muted transition hover:bg-[var(--hover-fill)] hover:text-secondary">
          {t("common.cancel")}
        </button>
      </div>
    </div>
  );
}

function IncomingPreview({ transfer, t }: { transfer: TransferStart; t: (k: string) => string }) {
  const fileWord = transfer.file_count === 1 ? t("transfer.fileOne") : t("transfer.fileMany");
  return (
    <div className="mt-3 max-h-40 space-y-1 overflow-auto rounded-xl border border-sky-300/10 bg-[var(--hover-fill)] p-2 text-left">
      <p className="px-1 text-xs text-subtle">{transfer.file_count} {fileWord} · {formatBytes(transfer.total)}</p>
      {transfer.items.map((it, i) => (
        <div key={i} className="flex items-center justify-between px-1 py-0.5">
          <span className="min-w-0 truncate text-xs text-secondary">{it.name}</span>
          <span className="ml-2 shrink-0 font-mono-num text-xs text-muted">{formatBytes(it.size)}</span>
        </div>
      ))}
      {transfer.file_count > transfer.items.length && (
        <p className="px-1 text-xs text-muted">+{transfer.file_count - transfer.items.length}</p>
      )}
    </div>
  );
}

function PendingTransferModal({ transfer, t, formatBytes, leftSec, saveDirLabel, onChooseSaveDir, onAccept, onReject }: {
  transfer: TransferStart;
  t: (k: string) => string;
  formatBytes: (n: number) => string;
  leftSec: number;
  saveDirLabel: string;
  onChooseSaveDir: () => void;
  onAccept: () => void;
  onReject: () => void;
}) {
  const fileWord = transfer.file_count === 1 ? t("transfer.fileOne") : t("transfer.fileMany");
  const panelRef = useRef<HTMLDivElement>(null);
  useFocusTrap(true, panelRef);

  useEffect(() => {
    const h = (e: KeyboardEvent) => { if (e.key === "Escape") onReject(); };
    window.addEventListener("keydown", h);
    return () => window.removeEventListener("keydown", h);
  }, [onReject]);

  return (
    <div role="dialog" aria-modal="true" aria-labelledby="pending-transfer-title"
      className="absolute inset-0 z-[60] flex items-center justify-center overflow-y-auto bg-black/70 p-6 backdrop-blur-sm">
      <div ref={panelRef} className="frost-panel animate-fade-in my-auto w-full max-w-md max-h-full overflow-y-auto rounded-2xl p-6">
        <h2 id="pending-transfer-title" className="text-xl font-semibold text-heading">{t("transfer.pending.title")}</h2>
        <p className="mt-2 text-sm text-muted">{t("transfer.pending.desc")}</p>
        <p className="mt-2 text-xs text-subtle">{t("transfer.pending.expires").replace("{n}", String(leftSec))}</p>
        <p className="mt-4 text-xs text-subtle">{transfer.file_count} {fileWord} · {formatBytes(transfer.total)}</p>
        <div className="mt-3 max-h-40 space-y-1 overflow-auto">
          {transfer.items.map((it, i) => (
            <div key={i} className="flex items-center justify-between rounded-lg bg-[var(--hover-fill)] px-3 py-1.5 text-xs">
              <div className="flex min-w-0 items-center gap-2">
                <Icon name={it.name.endsWith("/") ? "folder" : "file"} className="shrink-0 text-subtle" />
                <span className="truncate text-secondary">{it.name}</span>
              </div>
              <span className="ml-2 shrink-0 font-mono-num text-subtle">{formatBytes(it.size)}</span>
            </div>
          ))}
          {transfer.file_count > transfer.items.length && (
            <p className="px-1 text-xs text-muted">+{transfer.file_count - transfer.items.length}</p>
          )}
        </div>
        <p className="mt-3 max-w-full truncate text-xs text-muted" title={saveDirLabel}>↧ {saveDirLabel}</p>
        <button type="button" onClick={onChooseSaveDir}
          className="mt-2 w-full min-h-11 rounded-xl border border-sky-300/15 bg-[var(--hover-fill)] px-4 py-2.5 text-sm font-medium text-accent-strong transition hover:bg-[var(--hover-fill)] active:scale-[0.99]">
          {t("settings.saveDirChoose")}
        </button>
        <div className="mt-6 flex gap-2">
          <button type="button" onClick={onReject}
            className="flex-1 min-h-11 rounded-xl border border-sky-300/15 bg-[var(--hover-fill)] px-4 py-3 text-sm font-medium text-secondary transition hover:bg-[var(--hover-fill)] active:scale-[0.99]">
            {t("transfer.pending.reject")}
          </button>
          <button type="button" onClick={onAccept}
            className="frost-glow flex-1 min-h-11 rounded-xl bg-gradient-to-r from-sky-400 via-sky-500 to-cyan-500 px-4 py-3 text-sm font-medium text-white transition hover:brightness-110 active:scale-[0.99]">
            {t("transfer.pending.accept")}
          </button>
        </div>
      </div>
    </div>
  );
}

/* ---------- icons (consistent Feather-style, strokeWidth 2) ---------- */
function Icon({ name, className = "" }: { name: "upload" | "download" | "file" | "folder" | "lock" | "alert" | "gear" | "close" | "check" | "info"; className?: string }) {
  const base = { viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", strokeWidth: 2, strokeLinecap: "round" as const, strokeLinejoin: "round" as const, className };
  switch (name) {
    case "upload": return <svg {...base} width={18} height={18}><path d="M12 16V4M7 9l5-5 5 5M5 20h14" /></svg>;
    case "download": return <svg {...base} width={18} height={18}><path d="M12 4v12M7 11l5 5 5-5M5 20h14" /></svg>;
    case "file": return <svg {...base} width={14} height={14}><path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z" /><path d="M14 3v5h5" /></svg>;
    case "folder": return <svg {...base} width={14} height={14}><path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z" /></svg>;
    case "lock": return <svg {...base} width={12} height={12}><rect x="4" y="11" width="16" height="9" rx="2" /><path d="M8 11V8a4 4 0 0 1 8 0v3" /></svg>;
    case "alert": return <svg {...base} width={16} height={16}><path d="M12 9v4M12 17h.01M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z" /></svg>;
    case "gear": return <svg {...base} width={16} height={16}><circle cx="12" cy="12" r="3" /><path d="M12 2v3M12 19v3M4.2 4.2l2.1 2.1M17.7 17.7l2.1 2.1M2 12h3M19 12h3M4.2 19.8l2.1-2.1M17.7 6.3l2.1-2.1" /></svg>;
    case "close": return <svg {...base} width={18} height={18}><path d="M18 6 6 18M6 6l12 12" /></svg>;
    case "check": return <svg {...base} width={14} height={14}><path d="M20 6 9 17l-5-5" /></svg>;
    case "info": return <svg {...base} width={14} height={14}><circle cx="12" cy="12" r="9" /><path d="M12 11v5M12 8h.01" /></svg>;
  }
}
