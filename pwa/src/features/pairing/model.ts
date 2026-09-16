import { t } from "../../lib/i18n";
import { normalizeCrockford } from "../../lib/protocol/bytes";
import { normalizePassword, WEAK_PASSWORD_BYTES } from "../../lib/pairing-password";
import { pairProgress, type PairErrorField, type PairStep, type PairStepKey } from "../../lib/ui-model";
import { parsePairLocator, type FragmentPairing } from "../../lib/pairing-input";

export type ConnectNotice = { text: string; tone: "error" | "status" };

/**
 * Pure projection for the connect/pairing screen. The caller supplies the
 * handshake input, connection phase and notice; this file does not read state.
 */

export type ConnectViewInput = {
  phase: string;
  addingComputer: boolean;
  computerCount: number;
  fragment: FragmentPairing | null;
  pairCodeDraft: string;
  pairManualOpen: boolean;
  pairErrorTarget: PairErrorField;
  pairFailedStep: PairStepKey | null;
  pairAwaitingApproval: boolean;
  notice: ConnectNotice | null;
  desk: boolean;
  pairPasswordDraft: string;
  pairPasswordOpen: boolean;
  pairPasswordVisible: boolean;
  pairPasswordLocDraft: string;
};

export type ConnectViewModel = {
  pageClass: string;
  adding: boolean;
  busy: boolean;
  scanned: boolean;
  addingComputer: boolean;
  backTitle: string;
  title: string | null;
  lede: string;
  deskHint: string | null;
  qrNote: string | null;
  showGlobalNotice: boolean;
  waitTitle: string;
  waitCopy: string;
  rail: PairStep[];
  railNote: string | null;
  showFailedRail: boolean;
  pairCodeDraft: string;
  pairCodeLength: number;
  pairCodeComplete: boolean;
  pairCodeInvalid: boolean;
  manualOpen: boolean;
  passwordOpen: boolean;
  passwordDraft: string;
  passwordVisible: boolean;
  passwordLocDraft: string;
  /** UTF-8 bytes, the unit the daemon bounds — not the character count. */
  passwordBytes: number;
  passwordReady: boolean;
  passwordWeak: boolean;
  passwordInvalid: boolean;
  passwordLocInvalid: boolean;
};

export function connectViewModel(input: ConnectViewInput): ConnectViewModel {
  const busy = input.phase === "pairing";
  const scanned = input.fragment !== null;
  const adding = input.addingComputer || input.computerCount > 0;
  const manualOpen = input.pairManualOpen || input.pairErrorTarget === "code";
  const railFailure = input.pairFailedStep && input.pairFailedStep !== "code" ? input.notice : null;
  const railNote = railFailure?.tone === "error" ? railFailure.text : null;
  const length = normalizeCrockford(input.pairCodeDraft).length;
  // The counter is in UTF-8 bytes, the unit the daemon
  // bounds, so a CJK passphrase is measured the way it will be validated.
  const password = normalizePassword(input.pairPasswordDraft);
  const passwordLoc = parsePairLocator(input.pairPasswordLocDraft);
  return {
    pageClass: adding ? "page settings-page" : `prelude${busy ? " pairing" : ""}`,
    adding,
    busy,
    scanned,
    addingComputer: input.addingComputer,
    backTitle: input.addingComputer ? t("settings.addComputer") : t("connect.pair"),
    title: adding ? null : t("connect.title"),
    lede: scanned ? t("connect.ledeScanned") : input.addingComputer ? t("connect.ledeAdd") : t("connect.ledeScan"),
    deskHint: input.desk && !adding && !scanned && !busy ? t("connect.deskHint") : null,
    qrNote: scanned ? t("connect.qrNote") : null,
    showGlobalNotice: !input.pairErrorTarget && !railNote && !!input.notice,
    waitTitle: input.pairAwaitingApproval ? t("connect.waitEnter") : t("connect.waitTitle"),
    waitCopy: input.pairAwaitingApproval ? t("connect.waitEnterCopy") : t("connect.waitCopy"),
    rail: pairProgress({
      pairing: busy,
      awaitingApproval: input.pairAwaitingApproval,
      failedStep: input.pairFailedStep,
    }),
    railNote,
    showFailedRail: !!input.pairFailedStep,
    pairCodeDraft: input.pairCodeDraft,
    pairCodeLength: length,
    pairCodeComplete: length === 14,
    pairCodeInvalid: input.pairErrorTarget === "code",
    manualOpen,
    // A gate failure keeps the rail open so the operator
    // can correct the passphrase without hunting for the disclosure again.
    passwordOpen: input.pairPasswordOpen
      || input.pairErrorTarget === "password" || input.pairErrorTarget === "passwordLoc",
    passwordDraft: input.pairPasswordDraft,
    passwordVisible: input.pairPasswordVisible,
    passwordLocDraft: input.pairPasswordLocDraft,
    passwordBytes: password.bytes,
    // Both halves must be usable before the button offers to spend an attempt
    // against the gate's throttle.
    passwordReady: password.ok && passwordLoc !== null,
    // Advisory only: a short passphrase is still accepted, because the daemon
    // accepts it and refusing here would just look broken.
    passwordWeak: password.ok && password.bytes < WEAK_PASSWORD_BYTES,
    passwordInvalid: input.pairErrorTarget === "password",
    passwordLocInvalid: input.pairErrorTarget === "passwordLoc",
  };
}
