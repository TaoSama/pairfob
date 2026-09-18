import { describe, expect, test } from "bun:test";
import { setLang, t } from "../../lib/i18n";
import { syncFeedback } from "./sync-feedback";

/**
 * What the account page says after a sync.
 *
 * The point of these cases is that every outcome is distinguishable. A sync that
 * worked used to render exactly what a sync that was never pressed rendered, and
 * a sealed vault rendered the same "try again" as a dropped connection; both read
 * as a dead button to the person holding the phone.
 */
describe("account sync feedback", () => {
  test("an untouched account says nothing", () => {
    expect(syncFeedback({ syncOutcome: "idle", syncCode: null })).toBeNull();
  });

  test("a successful sync is acknowledged rather than silent", () => {
    const feedback = syncFeedback({ syncOutcome: "ok", syncCode: null });
    expect(feedback).toEqual({ text: t("settings.accountSynced"), tone: "status" });
  });

  test("a sealed vault asks for the passphrase instead of a retry", () => {
    const feedback = syncFeedback({ syncOutcome: "sealed", syncCode: null });
    expect(feedback).toEqual({ text: t("settings.accountSyncSealed"), tone: "error" });
    // The retry sentence is the wrong instruction here and must not be reused.
    expect(feedback!.text).not.toBe(t("settings.accountSyncFailed"));
  });

  test("a failure names the causes that change what to do next", () => {
    expect(syncFeedback({ syncOutcome: "failed", syncCode: "conflict" })!.text)
      .toBe(t("settings.accountSyncConflict"));
    expect(syncFeedback({ syncOutcome: "failed", syncCode: "offline" })!.text)
      .toBe(t("account.error.offline"));
    expect(syncFeedback({ syncOutcome: "failed", syncCode: "bad_relay" })!.text)
      .toBe(t("account.error.offline"));
    expect(syncFeedback({ syncOutcome: "failed", syncCode: "rate_limited" })!.text)
      .toBe(t("account.error.rateLimited"));
    expect(syncFeedback({ syncOutcome: "failed", syncCode: "forbidden" })!.text)
      .toBe(t("account.error.forbidden"));
    expect(syncFeedback({ syncOutcome: "failed", syncCode: "too_large" })!.text)
      .toBe(t("settings.accountSyncTooLarge"));
  });

  test("an unrecognised code keeps the generic sentence rather than inventing one", () => {
    for (const code of [null, "internal", "something_new"]) {
      expect(syncFeedback({ syncOutcome: "failed", syncCode: code })!.text)
        .toBe(t("settings.accountSyncFailed"));
    }
  });

  test("every outcome has copy in both languages", () => {
    for (const lang of ["zh", "en"] as const) {
      setLang(lang);
      for (const outcome of ["ok", "sealed", "failed"] as const) {
        const feedback = syncFeedback({ syncOutcome: outcome, syncCode: null });
        expect(feedback).not.toBeNull();
        // A missing key resolves to the key itself, which would show a dotted
        // identifier on the phone rather than a sentence.
        expect(feedback!.text).not.toContain("settings.account");
        expect(feedback!.text.length).toBeGreaterThan(0);
      }
    }
  });
});
