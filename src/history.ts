export interface TransferRecord {
  id: string;
  at: number;
  direction: "sending" | "receiving";
  fileCount: number;
  totalBytes: number;
  ok: boolean;
  err?: string;
}

const KEY = "frostwall.transferHistory";
const MAX = 50;

function isHistoryEntry(value: unknown): value is TransferRecord {
  if (!value || typeof value !== "object") return false;
  const e = value as Record<string, unknown>;
  return (
    typeof e.id === "string" &&
    typeof e.at === "number" &&
    (e.direction === "sending" || e.direction === "receiving") &&
    typeof e.fileCount === "number" &&
    Number.isFinite(e.fileCount) &&
    e.fileCount >= 0 &&
    typeof e.totalBytes === "number" &&
    Number.isFinite(e.totalBytes) &&
    e.totalBytes >= 0 &&
    Number.isFinite(e.at) &&
    typeof e.ok === "boolean"
    && (e.err === undefined || (typeof e.err === "string" && e.err.length <= 240))
  );
}

export function loadHistory(): TransferRecord[] {
  try {
    const raw = localStorage.getItem(KEY);
    if (!raw) return [];
    const parsed: unknown = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    return parsed.filter(isHistoryEntry);
  } catch {
    return [];
  }
}

export function appendHistory(entry: Omit<TransferRecord, "id" | "at">): TransferRecord[] {
  const err = entry.err && entry.err.length > 240 ? entry.err.slice(0, 240) : entry.err;
  const next: TransferRecord = {
    ...entry,
    err,
    id: crypto.randomUUID(),
    at: Date.now(),
  };
  const list = [next, ...loadHistory()].slice(0, MAX);
  try {
    localStorage.setItem(KEY, JSON.stringify(list));
  } catch {
    /* storage full / disabled */
  }
  return list;
}
