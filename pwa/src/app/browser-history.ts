export type HistoryBackHandler = () => void;

let backHandler: HistoryBackHandler | null = null;
let historySyncing = false;

export function registerHistoryBackHandler(handler: HistoryBackHandler): () => void {
  backHandler = handler;
  return () => {
    if (backHandler === handler) backHandler = null;
  };
}

export function bindBrowserHistory(signal?: AbortSignal): () => void {
  if (typeof window === "undefined" || !window.history) return () => {};

  const onPopState = () => {
    if (historySyncing) return;
    historySyncing = true;
    try {
      backHandler?.();
    } finally {
      historySyncing = false;
    }
  };

  window.addEventListener("popstate", onPopState, { signal });
  return () => window.removeEventListener("popstate", onPopState);
}

export function pushBrowserHistory(screen: string, paneId?: string | null): void {
  if (typeof window === "undefined" || !window.history || historySyncing) return;
  const current = window.history.state as { screen?: string; paneId?: string | null } | null;
  if (current?.screen === screen && current?.paneId === (paneId ?? null)) return;
  try {
    window.history.pushState({ screen, paneId: paneId ?? null }, "");
  } catch {
    // Ignore pushState errors
  }
}
