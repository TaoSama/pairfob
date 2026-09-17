import { INVITE_CODE_RE, USERNAME_RE, type AccountState, type AccountUser } from "../../lib/account-api.ts";

/**
 * Pure projection for the account entry that now guards the pair screen.
 *
 * The screen asks one question before anything else: does this deployment have
 * an account yet, and is this phone signed in to it? The three answers are three
 * different forms, and picking between them is the only decision this file makes.
 *
 * It emits copy *codes* rather than sentences. The page resolves them, so the
 * rules here stay testable without a language loaded and the copy tables stay a
 * separate concern from the state machine.
 */

export type AccountStep = "loading" | "bootstrap" | "login" | "register" | "ready";

/** Minimum a person types. The origin never sees it; it stretches into the authenticator. */
export const MIN_PASSPHRASE = 8;

/** Matches the origin's ceiling, so an over-long entry is refused here rather than at the server. */
export const MAX_PASSPHRASE = 128;

export type AccountDraft = {
  serviceToken: string;
  username: string;
  password: string;
  confirm: string;
  inviteCode: string;
};

export const EMPTY_DRAFT: AccountDraft = {
  serviceToken: "",
  username: "",
  password: "",
  confirm: "",
  inviteCode: "",
};

export type AccountEntryInput = {
  /** Null while `/state` is still in flight; the form must not flash before then. */
  state: AccountState | null;
  /** The person asked to register with an invite rather than sign in. */
  wantsRegister: boolean;
  draft: AccountDraft;
  /** Which fields the person has left, so an untouched form shows no complaints. */
  touched: readonly AccountField[];
  busy: boolean;
  /** The last failure's protocol code, or null. */
  errorCode: string | null;
};

export type AccountField = "serviceToken" | "username" | "password" | "confirm" | "inviteCode";

export type FieldView = {
  field: AccountField;
  value: string;
  /** Set once the field has been left and is still wrong; null while it is being typed. */
  problem: string | null;
};

export type AccountEntryModel = {
  step: AccountStep;
  /** The signed-in identity, or null. */
  user: AccountUser | null;
  fields: FieldView[];
  /** True when every field is filled and valid, and no request is in flight. */
  canSubmit: boolean;
  busy: boolean;
  /** A copy code for the whole form's failure, or null. Distinct from per-field problems. */
  notice: string | null;
  /**
   * Whether the person may switch to the invite form. Bootstrap has no account to
   * sign in to, and a signed-in phone has nothing to switch to.
   */
  canOfferRegister: boolean;
};

/** Which fields each step actually collects. */
const FIELDS: Record<Exclude<AccountStep, "loading" | "ready">, AccountField[]> = {
  bootstrap: ["serviceToken", "password", "confirm"],
  login: ["username", "password"],
  register: ["username", "password", "confirm", "inviteCode"],
};

/**
 * Failures the person can act on, mapped to their own copy.
 *
 * `locked_out` is deliberately not folded into `rate_limited`: it is the
 * three-strikes rule and lasts an hour, and telling someone to "try again
 * shortly" when the answer is "in an hour" wastes their evening.
 */
const NOTICES: Record<string, string> = {
  bad_credentials: "account.error.badCredentials",
  bad_invite: "account.error.badInvite",
  locked_out: "account.error.lockedOut",
  rate_limited: "account.error.rateLimited",
  conflict: "account.error.usernameTaken",
  invite_suspended: "account.error.inviteSuspended",
  already_initialized: "account.error.alreadyInitialized",
  bad_token: "account.error.badServiceToken",
  forbidden: "account.error.forbidden",
  bad_relay: "account.error.offline",
};

/**
 * A lockout is scoped to the credential that was got wrong, so the way out
 * differs by form. Three bad invite codes suspend registration but leave sign-in
 * working, and someone who already has an account should be told that rather
 * than left waiting an hour for a door that is not locked. Three bad passwords
 * suspend sign-in and leave registration alone.
 */
const LOCKOUTS: Partial<Record<AccountStep, string>> = {
  register: "account.error.lockedOutInvite",
  login: "account.error.lockedOutLogin",
};

function noticeFor(errorCode: string | null, current: AccountStep): string | null {
  if (!errorCode) return null;
  if (errorCode === "locked_out") return LOCKOUTS[current] ?? "account.error.lockedOut";
  return NOTICES[errorCode] ?? "account.error.unknown";
}

export function step(state: AccountState | null, wantsRegister: boolean): AccountStep {
  if (!state) return "loading";
  if (state.user) return "ready";
  if (!state.initialized) return "bootstrap";
  return wantsRegister ? "register" : "login";
}

function problemOf(field: AccountField, draft: AccountDraft): string | null {
  const value = draft[field];
  if (!value) return "account.problem.required";
  switch (field) {
    case "username":
      return USERNAME_RE.test(value) ? null : "account.problem.username";
    case "password":
      if (value.length < MIN_PASSPHRASE) return "account.problem.passphraseShort";
      return value.length > MAX_PASSPHRASE ? "account.problem.passphraseLong" : null;
    case "confirm":
      return value === draft.password ? null : "account.problem.confirmMismatch";
    case "inviteCode":
      // Codes are read off a screen and typed by hand, so case is forgiven here
      // rather than rejecting a correct code for being lowercase.
      return INVITE_CODE_RE.test(value.toUpperCase()) ? null : "account.problem.inviteCode";
    default:
      return null;
  }
}

export function accountEntryModel(input: AccountEntryInput): AccountEntryModel {
  const current = step(input.state, input.wantsRegister);
  const touched = new Set(input.touched);
  const collected = current === "loading" || current === "ready" ? [] : FIELDS[current];
  const fields = collected.map((field) => {
    const problem = problemOf(field, input.draft);
    return { field, value: input.draft[field], problem: touched.has(field) ? problem : null };
  });
  const complete = collected.every((field) => problemOf(field, input.draft) === null);
  return {
    step: current,
    user: input.state?.user ?? null,
    fields,
    canSubmit: complete && !input.busy && collected.length > 0,
    busy: input.busy,
    notice: noticeFor(input.errorCode, current),
    canOfferRegister: current === "login" || current === "register",
  };
}

/** What the submit button actually does, so the page does not re-derive it from the step. */
export type AccountSubmission =
  | { kind: "bootstrap"; serviceToken: string; password: string }
  | { kind: "login"; username: string; password: string }
  | { kind: "register"; username: string; password: string; inviteCode: string };

export function submissionFor(model: AccountEntryModel, draft: AccountDraft): AccountSubmission | null {
  if (!model.canSubmit) return null;
  switch (model.step) {
    case "bootstrap":
      // The first account's name is fixed; only the passphrase is the person's choice.
      return { kind: "bootstrap", serviceToken: draft.serviceToken, password: draft.password };
    case "login":
      return { kind: "login", username: draft.username, password: draft.password };
    case "register":
      return {
        kind: "register",
        username: draft.username,
        password: draft.password,
        inviteCode: draft.inviteCode.toUpperCase(),
      };
    default:
      return null;
  }
}

/** The username the bootstrap form will create, shown read-only beside the passphrase. */
export const BOOTSTRAP_USERNAME = "admin";
