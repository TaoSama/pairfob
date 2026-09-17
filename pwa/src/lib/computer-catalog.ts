import { t } from "./i18n.ts";
import type { PairResult } from "./protocol/client.ts";

const BURNED_CODES = new Set([
  "revoked",
  "unpaired",
  "invalid_credential",
  "bad_proof",
  "bad_signature",
  "fp_mismatch",
]);

const KNOWN_SSH_ALIASES: Record<string, string> = {
  "n37-080-152": "devbox",
  "n199-199-240": "devsg",
  "n37-212-222": "devos",
  "Mac-mini": "macmini",
  "macmini": "macmini",
};

const DAEMON_SSH_ALIASES: Record<string, string> = {
  "d_e64cf84bee9b55c19a87": "devbox",
  "d_a2a31b2efb50c89f4581": "devsg",
  "d_dbfc16e899be94e4ebfa": "devbox-prod",
  "d_c48b9a1b125dc814b4ce": "devos",
};

export function credentialIsBurned(code: string | undefined): boolean {
  return typeof code === "string" && BURNED_CODES.has(code);
}

/**
 * What to call a machine in the interface.
 *
 * Prefers standard SSH aliases when known (e.g. devbox, devsg, devos, macmini),
 * followed by the computer's reported hostname.
 */
export function computerTitle(pair: PairResult): string {
  if (pair.daemonId && DAEMON_SSH_ALIASES[pair.daemonId]) {
    return DAEMON_SSH_ALIASES[pair.daemonId];
  }
  const label = pair.label?.trim();
  if (label && (label === "devbox" || label === "devsg" || label === "devos" || label === "devbox-prod" || label === "macmini")) {
    return label;
  }
  const host = pair.hostname?.trim();
  if (host) {
    if (host === "n37-080-152") {
      return label === "devbox-prod" ? "devbox-prod" : "devbox";
    }
    if (KNOWN_SSH_ALIASES[host]) {
      return KNOWN_SSH_ALIASES[host];
    }
    return host;
  }
  return t("computer.unnamed");
}

export function pickResumeCredential(credentials: PairResult[], lastUsedDaemonId: string | null): PairResult | null {
  if (!credentials.length) return null;
  if (lastUsedDaemonId) {
    const match = credentials.find((item) => item.daemonId === lastUsedDaemonId);
    if (match) return match;
  }
  return sortComputers(credentials, lastUsedDaemonId)[0] ?? null;
}

export function sortComputers(credentials: PairResult[], lastUsedDaemonId: string | null): PairResult[] {
  return [...credentials].sort((a, b) => {
    if (lastUsedDaemonId) {
      if (a.daemonId === lastUsedDaemonId) return -1;
      if (b.daemonId === lastUsedDaemonId) return 1;
    }
    const seen = (b.lastSeen || b.createdAt) - (a.lastSeen || a.createdAt);
    if (seen) return seen;
    return a.daemonId.localeCompare(b.daemonId);
  });
}

export function phaseAfterComputers(count: number): "pick" | "connect" {
  return count > 0 ? "pick" : "connect";
}
