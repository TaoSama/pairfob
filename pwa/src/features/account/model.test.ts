import { describe, expect, test } from "bun:test";
import {
  accountEntryModel,
  BOOTSTRAP_USERNAME,
  EMPTY_DRAFT,
  MAX_PASSPHRASE,
  step,
  submissionFor,
  type AccountDraft,
  type AccountEntryInput,
  type AccountField,
} from "./model";

const ADMIN = { userId: "u_0123456789abcdef", username: "admin", role: "admin" as const };

function draft(over: Partial<AccountDraft> = {}): AccountDraft {
  return { ...EMPTY_DRAFT, ...over };
}

function model(over: Partial<AccountEntryInput> = {}) {
  return accountEntryModel({
    state: { initialized: true, user: null },
    wantsRegister: false,
    draft: EMPTY_DRAFT,
    touched: [],
    busy: false,
    errorCode: null,
    ...over,
  });
}

const ALL: AccountField[] = ["serviceToken", "username", "password", "confirm", "inviteCode"];

describe("which form the pair screen shows", () => {
  test("nothing is offered until the relay has answered", () => {
    // Flashing the bootstrap form and then replacing it with a login form would
    // invite someone to type a service token they do not need.
    expect(step(null, false)).toBe("loading");
    expect(model({ state: null }).fields).toEqual([]);
  });

  test("a deployment with no account opens the service-token form", () => {
    expect(step({ initialized: false, user: null }, false)).toBe("bootstrap");
  });

  test("a deployment that already has an account never reopens bootstrap", () => {
    // The route is closed server-side too, but offering it would send the person
    // hunting for a token that cannot help them.
    expect(step({ initialized: true, user: null }, false)).toBe("login");
    expect(step({ initialized: true, user: null }, true)).toBe("register");
  });

  test("a signed-in phone is past the entry entirely", () => {
    const view = model({ state: { initialized: true, user: ADMIN } });
    expect(view.step).toBe("ready");
    expect(view.fields).toEqual([]);
    expect(view.user).toEqual(ADMIN);
    expect(view.canSubmit).toBeFalse();
  });

  test("the invite form is offered from sign-in but not from bootstrap", () => {
    // Before the first account exists there is nobody to have issued an invite.
    expect(model({ state: { initialized: false, user: null } }).canOfferRegister).toBeFalse();
    expect(model().canOfferRegister).toBeTrue();
  });

  test("each form collects only the fields it needs", () => {
    const fields = (input: Partial<AccountEntryInput>) => model(input).fields.map((f) => f.field);
    expect(fields({ state: { initialized: false, user: null } })).toEqual([
      "serviceToken", "password", "confirm",
    ]);
    expect(fields({})).toEqual(["username", "password"]);
    expect(fields({ wantsRegister: true })).toEqual(["username", "password", "confirm", "inviteCode"]);
  });
});

describe("what the form complains about", () => {
  test("an untouched form shows no problems", () => {
    // Red text before the first keystroke reads as though something is broken.
    expect(model({ wantsRegister: true }).fields.every((f) => f.problem === null)).toBeTrue();
  });

  test("a field reports its problem once the person has left it", () => {
    const view = model({ wantsRegister: true, touched: ALL, draft: draft({ username: "A B" }) });
    const problems = Object.fromEntries(view.fields.map((f) => [f.field, f.problem]));
    expect(problems.username).toBe("account.problem.username");
    expect(problems.password).toBe("account.problem.required");
    expect(problems.inviteCode).toBe("account.problem.required");
  });

  test("a mismatched confirmation is named as such, not as a bad passphrase", () => {
    const view = model({
      wantsRegister: true,
      touched: ALL,
      draft: draft({ password: "hunter2hunter2", confirm: "hunter2hunter3" }),
    });
    expect(view.fields.find((f) => f.field === "confirm")?.problem).toBe("account.problem.confirmMismatch");
  });

  test("a short passphrase is rejected here rather than at the origin", () => {
    const view = model({ touched: ALL, draft: draft({ username: "admin", password: "short" }) });
    expect(view.fields.find((f) => f.field === "password")?.problem).toBe("account.problem.passphraseShort");
  });

  test("a passphrase past the origin's ceiling is refused before the round trip", () => {
    // The origin rejects it as a bad password, which reads as a typo rather than
    // a length limit.
    const long = "x".repeat(MAX_PASSPHRASE + 1);
    const view = model({ touched: ALL, draft: draft({ username: "admin", password: long }) });
    expect(view.fields.find((f) => f.field === "password")?.problem).toBe("account.problem.passphraseLong");
  });

  test("an invite code typed in lowercase is accepted", () => {
    // It is read off someone else's screen and typed by hand; rejecting the case
    // would fail a correct code.
    const view = model({
      wantsRegister: true,
      touched: ALL,
      draft: draft({ username: "bob", password: "hunter2hunter2", confirm: "hunter2hunter2", inviteCode: "wxyz" }),
    });
    expect(view.fields.find((f) => f.field === "inviteCode")?.problem).toBeNull();
    expect(view.canSubmit).toBeTrue();
  });

  test("a code of the wrong shape is refused", () => {
    const bad = (inviteCode: string) =>
      model({ wantsRegister: true, touched: ALL, draft: draft({ inviteCode }) })
        .fields.find((f) => f.field === "inviteCode")?.problem;
    expect(bad("ABC")).toBe("account.problem.inviteCode");
    expect(bad("ABCDE")).toBe("account.problem.inviteCode");
    expect(bad("AB1D")).toBe("account.problem.inviteCode");
  });
});

describe("when the form may be submitted", () => {
  const valid = draft({ username: "admin", password: "hunter2hunter2", confirm: "hunter2hunter2" });

  test("a complete sign-in may be submitted even with nothing touched", () => {
    // Autofill leaves a valid form nobody typed into; refusing it would strand
    // the person on a button that never enables.
    expect(model({ draft: valid }).canSubmit).toBeTrue();
  });

  test("a request in flight blocks a second submission", () => {
    // Two sign-ins race to set the session, and the loser's vault key wins.
    expect(model({ draft: valid, busy: true }).canSubmit).toBeFalse();
  });

  test("a signed-in or loading screen submits nothing", () => {
    expect(model({ state: null, draft: valid }).canSubmit).toBeFalse();
    expect(model({ state: { initialized: true, user: ADMIN }, draft: valid }).canSubmit).toBeFalse();
  });

  test("bootstrap creates the fixed first username, not whatever is in the field", () => {
    const filled = draft({
      serviceToken: "svc", username: "someone-else",
      password: "hunter2hunter2", confirm: "hunter2hunter2",
    });
    const view = model({ state: { initialized: false, user: null }, draft: filled });
    const submission = submissionFor(view, filled);
    expect(submission).toEqual({ kind: "bootstrap", serviceToken: "svc", password: "hunter2hunter2" });
    expect(BOOTSTRAP_USERNAME).toBe("admin");
  });

  test("registration normalizes the invite code before it is sent", () => {
    // The origin compares against four uppercase letters; sending "wxyz" would
    // be refused as a wrong code.
    const filled = draft({
      username: "bob", password: "hunter2hunter2", confirm: "hunter2hunter2", inviteCode: "wxyz",
    });
    const view = model({ wantsRegister: true, draft: filled });
    expect(submissionFor(view, filled)).toEqual({
      kind: "register", username: "bob", password: "hunter2hunter2", inviteCode: "WXYZ",
    });
  });

  test("an incomplete form yields no submission at all", () => {
    const partial = draft({ username: "admin" });
    expect(submissionFor(model({ draft: partial }), partial)).toBeNull();
  });
});

describe("what a failure tells the person", () => {
  test("the hour-long lockout is not reported as ordinary throttling", () => {
    // One asks them to wait a moment, the other an hour; collapsing them sends
    // someone back to a form that will refuse them for the next sixty minutes.
    // The bootstrap form has no other door to point at, so it gets the plain
    // sentence; the two forms that do are covered below.
    const bootstrap = { initialized: false, user: null };
    expect(model({ state: bootstrap, errorCode: "locked_out" }).notice).toBe("account.error.lockedOut");
    expect(model({ errorCode: "rate_limited" }).notice).toBe("account.error.rateLimited");
  });

  test("a lockout names the way out that is still open", () => {
    // The budget is per credential kind: three bad invite codes suspend
    // registration and leave sign-in working, and the reverse. A single
    // "try again later" would strand someone who has an account and only needs
    // the other form.
    const onRegister = model({ state: { initialized: true, user: null }, wantsRegister: true, errorCode: "locked_out" });
    expect(onRegister.notice).toBe("account.error.lockedOutInvite");
    const onLogin = model({ state: { initialized: true, user: null }, errorCode: "locked_out" });
    expect(onLogin.notice).toBe("account.error.lockedOutLogin");
  });

  test("a suspended invite code is not presented as something to retry", () => {
    // Retrying a suspended code can never succeed; the way out is an admin
    // rotating it, which is a different sentence from "that code is wrong".
    const view = model({ state: { initialized: true, user: null }, wantsRegister: true, errorCode: "invite_suspended" });
    expect(view.notice).toBe("account.error.inviteSuspended");
    expect(view.notice).not.toBe(model({ errorCode: "bad_invite" }).notice);
  });

  test("a wrong invite code is distinguished from a wrong passphrase", () => {
    expect(model({ errorCode: "bad_invite" }).notice).toBe("account.error.badInvite");
    expect(model({ errorCode: "bad_credentials" }).notice).toBe("account.error.badCredentials");
  });

  test("a taken username is named rather than reported as a server fault", () => {
    expect(model({ errorCode: "conflict" }).notice).toBe("account.error.usernameTaken");
  });

  test("an unrecognized code still produces a notice rather than silence", () => {
    // A failed sign-in with no message looks like a dead button.
    expect(model({ errorCode: "wat" }).notice).toBe("account.error.unknown");
  });

  test("no failure means no notice", () => {
    expect(model().notice).toBeNull();
  });
});
