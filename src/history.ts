export interface TransferRecord {
  id: string;
  at: number;
  direction: "sending" | "receiving";
  fileCount: number;
  totalBytes: number;
  ok: boolean;
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
    typeof e.totalBytes === "number" &&
    typeof e.ok === "boolean"
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
  const next: TransferRecord = {
    ...entry,
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
