export type Theme = "system" | "dark" | "light";

const KEY = "frostwall.theme";

export function readTheme(): Theme {
  try {
    const v = localStorage.getItem(KEY);
    if (v === "system" || v === "dark" || v === "light") return v;
  } catch {
    /* ignore */
  }
  return "system";
}

export function saveTheme(theme: Theme): void {
  try {
    localStorage.setItem(KEY, theme);
  } catch {
    /* ignore */
  }
}

export function applyTheme(theme: Theme): void {
  const root = document.documentElement;
  if (theme === "system") {
    root.removeAttribute("data-theme");
  } else {
    root.setAttribute("data-theme", theme);
  }
}

/** Re-apply theme when the OS appearance changes (system mode only). */
export function watchSystemTheme(onChange: () => void): () => void {
  const mq = window.matchMedia("(prefers-color-scheme: dark)");
  const handler = () => onChange();
  mq.addEventListener("change", handler);
  return () => mq.removeEventListener("change", handler);
}
