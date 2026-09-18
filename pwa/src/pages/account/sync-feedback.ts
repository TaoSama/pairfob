import { t } from "../../lib/i18n";
import type { FeedbackValue } from "../../shared/ui/primitives";

/**
 * Pure copy for the account sync result.
 *
 * Kept out of the component so the mapping from outcome to sentence is testable
 * without a DOM, and out of the store so the domain records what happened rather
 * than how it reads.
 *
 * The failure code is honoured where it changes the advice. "Retry" is the wrong
 * instruction for a losing compare-and-set that has already exhausted its retry,
 * and for a phone that is simply offline, so those name their own cause; anything
 * unrecognised keeps the generic sentence rather than inventing a diagnosis.
 */
export type SyncFeedbackInput = {
  syncOutcome: "idle" | "ok" | "sealed" | "failed";
  syncCode: string | null;
};

export function syncFeedback(input: SyncFeedbackInput): FeedbackValue | null {
  switch (input.syncOutcome) {
    case "idle":
      return null;
    case "ok":
      return { text: t("settings.accountSynced"), tone: "status" };
    case "sealed":
      return { text: t("settings.accountSyncSealed"), tone: "error" };
    case "failed":
      return { text: syncFailureCopy(input.syncCode), tone: "error" };
  }
}

function syncFailureCopy(code: string | null): string {
  switch (code) {
    case "conflict":
      return t("settings.accountSyncConflict");
    case "offline":
    case "bad_relay":
      return t("account.error.offline");
    case "rate_limited":
      return t("account.error.rateLimited");
    case "forbidden":
      return t("account.error.forbidden");
    case "too_large":
      return t("settings.accountSyncTooLarge");
    default:
      return t("settings.accountSyncFailed");
  }
}
