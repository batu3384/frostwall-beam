export interface TransferRecord {
  id: number;
  at: number;
  direction: "sending" | "receiving";
  fileCount: number;
  totalBytes: number;
  ok: boolean;
}

const KEY = "frostwall.transferHistory";
const MAX = 50;

export function loadHistory(): TransferRecord[] {
  try {
    const raw = localStorage.getItem(KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw) as TransferRecord[];
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

export function appendHistory(entry: Omit<TransferRecord, "id" | "at">): TransferRecord[] {
  const next: TransferRecord = {
    ...entry,
    id: Date.now(),
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
