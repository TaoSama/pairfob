import { useCallback, useState, useSyncExternalStore } from "react";
import { langRevision, subscribeLang } from "../../lib/i18n";
import { useAccount } from "../../features/account/hooks";
import { AccountEntryView } from "../../features/account/account-view";
import {
  accountEntryModel,
  submissionFor,
  EMPTY_DRAFT,
  type AccountDraft,
  type AccountField,
} from "../../features/account/model";
import {
  chooseRegisterForm,
  claimPairedDevice,
  submitAccountEntry,
} from "./account-controller";

/**
 * Account page composition.
 *
 * The draft is component state rather than a domain field, and that is the
 * security boundary this page exists to hold: a passphrase kept in a published
 * snapshot would be deep-frozen into the frame, survive the form, and be
 * readable by anything that can reach the store. Here it lives for exactly as
 * long as the form is mounted, is handed to the controller as an argument, and
 * goes with the unmount.
 *
 * Everything the rest of the application needs to see — who is signed in, which
 * machines they own, whether a request is in flight — is domain state, so the
 * page re-renders from `useAccount()` and never from a local copy of it.
 */

/** Re-render mounted copy on the i18n revision (advances on every applied language action). */
function useLang(): void {
  useSyncExternalStore(subscribeLang, langRevision);
}

export function AccountScreen() {
  const account = useAccount();
  useLang();
  const [draft, setDraft] = useState<AccountDraft>(EMPTY_DRAFT);
  const [touched, setTouched] = useState<AccountField[]>([]);

  const onChange = useCallback((field: AccountField, value: string) => {
    setDraft((current) => ({ ...current, [field]: value }));
  }, []);
  const onBlur = useCallback((field: AccountField) => {
    setTouched((current) => (current.includes(field) ? current : [...current, field]));
  }, []);

  const model = accountEntryModel({
    state: account.initialized === null ? null : {
      initialized: account.initialized,
      user: null,
    },
    wantsRegister: account.wantsRegister,
    draft,
    touched,
    busy: account.busy,
    errorCode: account.errorCode,
    errorRemaining: account.errorRemaining,
  });

  return (
    <AccountEntryView
      model={model}
      onChange={onChange}
      onBlur={onBlur}
      onToggleRegister={(wantsRegister) => {
        setTouched([]);
        chooseRegisterForm(wantsRegister);
      }}
      onSubmit={(event) => {
        event.preventDefault();
        const submission = submissionFor(model, draft);
        if (!submission) return;
        void submitAccountEntry(submission).then((ok) => {
          // The passphrase is dropped the moment it is no longer needed, and
          // only on success: a refused attempt leaves what was typed in place so
          // the person can fix one character instead of retyping everything.
          if (ok) {
            setDraft(EMPTY_DRAFT);
            setTouched([]);
          }
        }).catch(() => {
          // The controller reports every failure it can name through the domain,
          // so there is nothing to add here. The handler exists so a contract
          // violation below it becomes a no-op on the form rather than an
          // unhandled rejection that leaves the page silent.
        });
      }}
    />
  );
}

export { claimPairedDevice };
