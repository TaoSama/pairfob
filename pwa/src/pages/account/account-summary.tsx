import { t } from "../../lib/i18n";
import { useAccount } from "../../features/account/hooks";
import { openAccountGate, signOutOfAccount, syncAccountVault } from "./account-controller";
import { Button, Feedback, SetHeading, SetRow } from "../../shared/ui/primitives";
import { syncFeedback } from "./sync-feedback";

/**
 * The account, from the one screen that is always reachable.
 *
 * Signing in is what carries a computer to another phone, so it cannot only be
 * offered at boot: a phone that already holds one credential resumes it and
 * never sees the account form. Here it is reachable whether or not anything is
 * connected.
 */
export function AccountSummary() {
  const account = useAccount();
  const signedIn = account.username !== null;
  const feedback = syncFeedback(account);
  return (
    <>
      <SetHeading text={t("settings.account")} help={[t("settings.accountNote")]} />
      <div className="set-card">
        {signedIn ? (
          <>
            <SetRow label={t("settings.accountSignedIn")} value={account.username ?? ""} />
            {feedback ? <Feedback value={feedback} /> : null}
            <div className="set-row set-row-stack">
              <Button
                className="btn btn-small account-sync"
                disabled={account.busy}
                aria-busy={account.busy}
                onClick={() => {
                  // The controller names every failure it can through the domain;
                  // this keeps a contract violation from becoming an unhandled
                  // rejection with nothing on screen.
                  void syncAccountVault(null).catch(() => undefined);
                }}
              >{t(account.busy ? "settings.accountSyncing" : "settings.accountSync")}</Button>
            </div>
            <div className="set-row set-row-stack">
              <Button
                className="btn btn-small btn-danger account-sign-out"
                disabled={account.busy}
                onClick={() => void signOutOfAccount()}
              >{t("settings.accountSignOut")}</Button>
            </div>
          </>
        ) : (
          <div className="set-row set-row-stack">
            <p className="set-note">{t("settings.accountSignedOut")}</p>
            <Button
              className="btn btn-small account-sign-in"
              disabled={account.busy}
              onClick={() => void openAccountGate()}
            >{t("settings.accountSignIn")}</Button>
          </div>
        )}
      </div>
    </>
  );
}
