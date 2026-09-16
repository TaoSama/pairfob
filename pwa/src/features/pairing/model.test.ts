import { describe, expect, test } from "bun:test";
import { setLang } from "../../lib/i18n";
import { connectViewModel } from "./model";

const empty = {
  phase: "connect",
  addingComputer: false,
  computerCount: 0,
  fragment: null,
  pairCodeDraft: "",
  pairPasswordDraft: "",
  pairPasswordLocDraft: "",
  pairManualOpen: false,
  pairErrorTarget: null as "code" | null,
  pairFailedStep: null,
  pairAwaitingApproval: false,
  notice: null,
  desk: false,
};

describe("connect view model", () => {
  test("first pairing is a prelude; add-computer uses settings chrome", () => {
    setLang("zh");
    const first = connectViewModel(empty);
    expect(first.pageClass).toBe("prelude");
    expect(first.title).toBe("连上你的电脑");
    expect(first.adding).toBeFalse();
    const add = connectViewModel({ ...empty, addingComputer: true });
    expect(add.pageClass).toBe("page settings-page");
    expect(add.backTitle).toBe("添加另一台电脑");
    expect(add.title).toBeNull();
    expect(add.lede).toContain("pairfob pair");
  });

  test("a pairing wait hides the scan form and an incomplete code is not marked complete", () => {
    setLang("zh");
    const wait = connectViewModel({ ...empty, phase: "pairing", pairAwaitingApproval: true });
    expect(wait.busy).toBeTrue();
    expect(wait.pageClass).toBe("prelude pairing");
    expect(wait.waitTitle).toContain("电脑");
    const draft = connectViewModel({ ...empty, pairCodeDraft: "ABCD-EFGH" });
    expect(draft.pairCodeLength).toBe(8);
    expect(draft.pairCodeComplete).toBeFalse();
  });

  test("a short passphrase is flagged weak but still submittable", () => {
    setLang("zh");
    // 11 bytes: over the daemon's 8-byte floor, under the nudge threshold.
    const weak = connectViewModel({ ...empty, pairPasswordDraft: "abcdefghijk", pairPasswordLocDraft: "WJ3K9M" });
    expect(weak.passwordBytes).toBe(11);
    expect(weak.passwordWeak).toBeTrue();
    // Advisory only: the submit must stay available.
    expect(weak.passwordReady).toBeTrue();

    const strong = connectViewModel({ ...empty, pairPasswordDraft: "abcdefghijkl", pairPasswordLocDraft: "WJ3K9M" });
    expect(strong.passwordBytes).toBe(12);
    expect(strong.passwordWeak).toBeFalse();

    // Too short to be valid at all is not "weak", it is rejected.
    const tooShort = connectViewModel({ ...empty, pairPasswordDraft: "abc" });
    expect(tooShort.passwordWeak).toBeFalse();
    expect(tooShort.passwordReady).toBeFalse();
  });
});
