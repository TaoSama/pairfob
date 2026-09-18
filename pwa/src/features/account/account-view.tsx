import type { FormEvent } from "react";
import { t, type CopyKey } from "../../lib/i18n";
import { Brand, Button, EmptyState, Feedback, Spinner } from "../../shared/ui/primitives";
import { BOOTSTRAP_USERNAME, type AccountEntryModel, type AccountField } from "./model";
import type { BoundDevice } from "../../lib/account-api";

/**
 * The account surface. Pure: every sentence arrives as a copy code the model
 * chose, every mutation is a callback, and nothing here reads a store or the
 * network.
 *
 * Two screens share the file because they are two states of one question — who
 * is this phone, and what does that account own — and splitting them would put
 * the sign-out control in a different module from the identity it signs out of.
 */

/** Per-field input shape. Passwords never autofill across the two password boxes. */
const FIELD_ATTRS: Record<AccountField, {
  type: string;
  autoComplete: string;
  inputMode?: "text" | "email";
  maxLength: number;
  uppercase?: boolean;
}> = {
  serviceToken: { type: "password", autoComplete: "off", maxLength: 200 },
  username: { type: "text", autoComplete: "username", maxLength: 32 },
  password: { type: "password", autoComplete: "current-password", maxLength: 128 },
  confirm: { type: "password", autoComplete: "new-password", maxLength: 128 },
  inviteCode: { type: "text", autoComplete: "one-time-code", maxLength: 4, uppercase: true },
};

/** The fields that carry a sentence of their own under the box. */
const HINTS: Partial<Record<AccountField, CopyKey>> = {
  serviceToken: "account.hint.serviceToken",
  password: "account.hint.password",
  inviteCode: "account.hint.inviteCode",
};

export function AccountEntryView({
  model, onChange, onBlur, onSubmit, onToggleRegister,
}: {
  model: AccountEntryModel;
  onChange: (field: AccountField, value: string) => void;
  onBlur: (field: AccountField) => void;
  onSubmit: (event: FormEvent<HTMLFormElement>) => void;
  onToggleRegister: (wantsRegister: boolean) => void;
}) {
  if (model.step === "loading") {
    return (
      <div className="page account-page">
        <Brand />
        <p className="lede" role="status">{t("account.loading")}</p>
        <Spinner />
      </div>
    );
  }
  const form = model.step === "bootstrap" ? "bootstrap" : model.step === "register" ? "register" : "login";
  return (
    <div className="page account-page">
      <Brand />
      <h1 className="prelude-title">{t(`account.title.${form}` as CopyKey)}</h1>
      <p className="lede">{t(`account.lede.${form}` as CopyKey)}</p>
      {model.notice ? (
        <Feedback
          value={{
            text: t(model.notice as CopyKey, model.noticeCount === null ? undefined : { count: model.noticeCount }),
            tone: "error",
          }}
        />
      ) : null}
      <form className="account-form" noValidate aria-busy={model.busy} onSubmit={onSubmit}>
        {form === "bootstrap" ? (
          <div className="account-fixed-user">
            <span className="field-label">{t("account.field.username")}</span>
            <code className="account-username">{BOOTSTRAP_USERNAME}</code>
          </div>
        ) : null}
        {model.fields.map((field) => (
          <AccountFieldRow
            key={field.field}
            field={field.field}
            value={field.value}
            problem={field.problem}
            busy={model.busy}
            onChange={onChange}
            onBlur={onBlur}
          />
        ))}
        <Button
          type="submit"
          className="btn btn-primary account-submit"
          disabled={!model.canSubmit}
        >{model.busy ? t("account.loading") : t(`account.submit.${form}` as CopyKey)}</Button>
      </form>
      {model.canOfferRegister ? (
        <Button
          className="btn btn-ghost btn-small account-switch-form"
          onClick={() => onToggleRegister(model.step !== "register")}
        >{model.step === "register" ? t("account.toLogin") : t("account.toRegister")}</Button>
      ) : null}
      <p className="trust">{t("account.trust")}</p>
    </div>
  );
}

function AccountFieldRow({
  field, value, problem, busy, onChange, onBlur,
}: {
  field: AccountField;
  value: string;
  problem: string | null;
  busy: boolean;
  onChange: (field: AccountField, value: string) => void;
  onBlur: (field: AccountField) => void;
}) {
  const attrs = FIELD_ATTRS[field];
  const id = `account-${field}`;
  const hint = HINTS[field];
  const describedBy = problem ? `${id}-problem` : hint ? `${id}-hint` : undefined;
  return (
    <label className="field" htmlFor={id}>
      <div className="field-head">
        <span className="field-label">{t(`account.field.${field}` as CopyKey)}</span>
      </div>
      <input
        id={id}
        name={field}
        type={attrs.type}
        value={value}
        disabled={busy}
        required
        maxLength={attrs.maxLength}
        autoComplete={attrs.autoComplete}
        autoCapitalize={attrs.uppercase ? "characters" : "off"}
        autoCorrect="off"
        spellCheck={false}
        className={attrs.uppercase ? "account-code-input" : undefined}
        aria-invalid={problem ? "true" : undefined}
        aria-describedby={describedBy}
        onInput={(event) => onChange(field, event.currentTarget.value)}
        onBlur={() => onBlur(field)}
      />
      {problem
        ? <Feedback value={{ text: t(problem as CopyKey), tone: "error" }} id={`${id}-problem`} />
        : hint ? <p className="field-hint" id={`${id}-hint`}>{t(hint)}</p> : null}
    </label>
  );
}
