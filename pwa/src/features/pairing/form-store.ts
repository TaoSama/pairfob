import type { PairErrorField, PairStepKey } from "../../lib/ui-model";
import { createDomain } from "../../shared/model/domain-store";

/**
 * Pairing domain: the add-computer handshake input and its failure rail.
 * Credentials and the computer list live in `computers.ts`; the origin/pairing
 * intent fragment lives in `connection.ts`.
 */
export type PairingRecord = {
  pairCodeDraft: string;
  pairManualOpen: boolean;
  pairErrorTarget: PairErrorField;
  /** Which of the three pairing steps the last attempt died on, for the rail. */
  pairFailedStep: PairStepKey | null;
  pairAwaitingApproval: boolean;
  pairAbort: AbortController | null;
  /**
   * The reusable-passphrase rail. It is a separate draft from the pairing code
   * because the two are folded differently, and switching entry mode must not
   * carry a half-typed code into the passphrase the PAKE will derive from.
   */
  pairPasswordDraft: string;
  pairPasswordOpen: boolean;
  pairPasswordVisible: boolean;
  /** The passphrase gate still needs a locator to find the daemon on the relay. */
  pairPasswordLocDraft: string;
};

/** `pairAbort` is an opaque handle: a controller is a live resource, not data. */
const pairingDomain = createDomain<PairingRecord, "pairAbort">("pairing", {
  pairCodeDraft: "",
  pairManualOpen: false,
  pairErrorTarget: null,
  pairFailedStep: null,
  pairAwaitingApproval: false,
  pairAbort: null,
  pairPasswordDraft: "",
  pairPasswordOpen: false,
  pairPasswordVisible: false,
  pairPasswordLocDraft: "",
}, { opaque: ["pairAbort"] });
export const pairingStore = pairingDomain.store;
const { read, write } = pairingDomain.controller;


export function setPairCodeDraft(code: string): void {
  if (read().pairCodeDraft === code) return;
  write((record) => {
    record.pairCodeDraft = code;
  });
}

export function setPairManualOpen(open: boolean): void {
  if (read().pairManualOpen === open) return;
  write((record) => {
    record.pairManualOpen = open;
  });
}

/** Mark the field and step a failed attempt died on, or clear both on success. */
export function setPairFailure(target: PairErrorField, step: PairStepKey | null): void {
  write((record) => {
    record.pairErrorTarget = target;
    record.pairFailedStep = step;
  });
}

export function setPairAwaitingApproval(awaiting: boolean): void {
  if (read().pairAwaitingApproval === awaiting) return;
  write((record) => {
    record.pairAwaitingApproval = awaiting;
  });
}

export function setPairAbort(controller: AbortController | null): void {
  write((record) => {
    record.pairAbort = controller;
  });
}

export function setPairPasswordDraft(password: string): void {
  if (read().pairPasswordDraft === password) return;
  write((record) => {
    record.pairPasswordDraft = password;
  });
}

export function setPairPasswordOpen(open: boolean): void {
  if (read().pairPasswordOpen === open) return;
  write((record) => {
    record.pairPasswordOpen = open;
    // Leaving the passphrase rail drops the secret rather than parking it in
    // the store where a later screen could read or publish it.
    if (!open) {
      record.pairPasswordDraft = "";
      record.pairPasswordVisible = false;
    }
  });
}

export function setPairPasswordVisible(visible: boolean): void {
  if (read().pairPasswordVisible === visible) return;
  write((record) => {
    record.pairPasswordVisible = visible;
  });
}

export function setPairPasswordLocDraft(loc: string): void {
  if (read().pairPasswordLocDraft === loc) return;
  write((record) => {
    record.pairPasswordLocDraft = loc;
  });
}

/**
 * Action-time readers for the pairing record. The abort handle is an opaque
 * live resource and is returned by identity; the rest are plain values read
 * from the coherent live record without a facade alias.
 */
export function pairAbortHandle(): AbortController | null {
  return read().pairAbort;
}

export function pairCodeDraft(): string {
  return read().pairCodeDraft;
}

export function pairManualOpen(): boolean {
  return read().pairManualOpen;
}

export function pairErrorTarget(): PairErrorField {
  return read().pairErrorTarget;
}

export function pairFailedStep(): PairStepKey | null {
  return read().pairFailedStep;
}

export function pairAwaitingApproval(): boolean {
  return read().pairAwaitingApproval;
}

export function pairPasswordDraft(): string {
  return read().pairPasswordDraft;
}

export function pairPasswordOpen(): boolean {
  return read().pairPasswordOpen;
}

export function pairPasswordVisible(): boolean {
  return read().pairPasswordVisible;
}

export function pairPasswordLocDraft(): string {
  return read().pairPasswordLocDraft;
}

/** Clear only the error field; the failure-step rail keeps its last step. */
export function clearPairErrorTarget(): void {
  if (read().pairErrorTarget === null) return;
  write((record) => {
    record.pairErrorTarget = null;
  });
}

/**
 * Clear the handshake input when a pairing attempt ends or the screen closes.
 * The passphrase is dropped with it: it is the PAKE secret, and a retained
 * draft would outlive the attempt that needed it.
 */
export function resetPairingInput(): void {
  write((record) => {
    record.pairCodeDraft = "";
    record.pairManualOpen = false;
    record.pairErrorTarget = null;
    record.pairFailedStep = null;
    record.pairAwaitingApproval = false;
    record.pairAbort = null;
    record.pairPasswordDraft = "";
    record.pairPasswordOpen = false;
    record.pairPasswordVisible = false;
    record.pairPasswordLocDraft = "";
  });
}
