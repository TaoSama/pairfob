import { useCallback, useEffect, useState } from "react";
import { readInviteCode, rotateInviteCode } from "../../lib/account-api";
import { t } from "../../lib/i18n";
import { useAccount } from "../../features/account/hooks";
import { Button, Feedback, SetHeading } from "../../shared/ui/primitives";

/**
 * The invite code, for the one account allowed to see it.
 *
 * This is the only thing an admin can do that an ordinary member cannot, and it
 * is deliberately small: everyone binds their own computers and nobody sees
 * anyone else's, so administration here is issuing a code and changing it.
 *
 * The code is component state rather than a domain field. Nothing else in the
 * application reads it, it is only meaningful while this section is on screen,
 * and it is read from the origin on mount rather than cached — an admin who
 * rotated it on another phone must not be shown the retired one from a snapshot.
 *
 * The relay decides who may read it. Rendering is gated on the role only so a
 * member is not shown a control that would refuse; it is not the access check.
 */
export function InviteCodeSection() {
  const account = useAccount();
  const [code, setCode] = useState<string | null>(null);
  const [failed, setFailed] = useState(false);
  const [busy, setBusy] = useState(false);
  const admin = account.role === "admin";

  useEffect(() => {
    if (!admin) return;
    // An unmount mid-flight must not write into a dead component, and a
    // rotation that lands while the first read is still in the air must not be
    // overwritten by the older answer.
    let live = true;
    setFailed(false);
    readInviteCode()
      .then((invite) => {
        if (live) setCode(invite.code);
      })
      .catch(() => {
        if (live) setFailed(true);
      });
    return () => {
      live = false;
    };
  }, [admin]);

  const rotate = useCallback(() => {
    setBusy(true);
    setFailed(false);
    rotateInviteCode()
      .then((invite) => setCode(invite.code))
      .catch(() => setFailed(true))
      .finally(() => setBusy(false));
  }, []);

  if (!admin) return null;
  return (
    <>
      <SetHeading text={t("account.invite.title")} help={[t("account.invite.note")]} />
      <div className="set-card">
        <div className="set-row set-row-stack">
          <code className="invite-code" aria-busy={busy || undefined}>
            {code ?? (failed ? "—" : t("account.invite.loading"))}
          </code>
          <Button className="btn btn-small invite-rotate" onClick={rotate} disabled={busy}>
            {t("account.invite.rotate")}
          </Button>
        </div>
      </div>
      {failed ? <Feedback value={{ text: t("account.invite.failed"), tone: "error" }} /> : null}
    </>
  );
}
