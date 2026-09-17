import { resetBoardTestDOM } from "../../../test-support/dom";
import { beforeEach, describe, expect, test } from "bun:test";
import { attachLiveSession, setCredential } from "../computers/catalog-store";
import { setPhase } from "../connection/connection-store";
import { resetGenerationsForTests } from "../connection/generations";
import type { DeviceSummary } from "../../lib/protocol/client";
import { syncDeviceLabel } from "./controller";

beforeEach(async () => {
  await resetBoardTestDOM();
  resetGenerationsForTests();
});

function device(partial: Partial<DeviceSummary> & Pick<DeviceSummary, "device_id">): DeviceSummary {
  return {
    label: "Mac", self: false, created_at: 1, last_seen: 1, connected: true,
    ...partial,
  } as DeviceSummary;
}

/** A live session that records the labels it was asked to store. */
function boot(): string[] {
  const renamed: string[] = [];
  setPhase("live");
  setCredential({
    daemonId: "d_aaaaaaaaaaaaaaaaaaaa", deviceId: "dev_phone",
    psk: new Uint8Array(32), daemonPk: new Uint8Array(32),
    relayOrigin: "https://pairfob.com", fp: "fp", label: "Studio", createdAt: 1,
  });
  attachLiveSession({
    isConnected: () => true,
    renameDevice: async (label: string) => { renamed.push(label); },
  } as never);
  return renamed;
}

describe("carrying a phone rename to a computer that missed it", () => {
  test("a computer still using the old name is corrected once", async () => {
    const renamed = boot();
    await syncDeviceLabel(
      [device({ device_id: "dev_phone", self: true, label: "Mac" })],
      async () => "Wentao 的手机",
    );
    expect(renamed).toEqual(["Wentao 的手机"]);
  });

  test("a computer already using the chosen name is left alone", async () => {
    const renamed = boot();
    await syncDeviceLabel(
      [device({ device_id: "dev_phone", self: true, label: "Wentao 的手机" })],
      async () => "Wentao 的手机",
    );
    expect(renamed).toEqual([]);
  });

  test("never renames another paired device", async () => {
    const renamed = boot();
    // Only the row this session owns is a rename target; a list without one
    // means there is nothing here to correct.
    await syncDeviceLabel(
      [device({ device_id: "dev_other", label: "Mac" })],
      async () => "Wentao 的手机",
    );
    expect(renamed).toEqual([]);
  });

  test("a phone that never chose a name leaves every computer as it is", async () => {
    const renamed = boot();
    await syncDeviceLabel(
      [device({ device_id: "dev_phone", self: true, label: "Mac" })],
      async () => null,
    );
    expect(renamed).toEqual([]);
  });

  test("an unreadable local store is not a reason to rename anything", async () => {
    const renamed = boot();
    await syncDeviceLabel(
      [device({ device_id: "dev_phone", self: true, label: "Mac" })],
      async () => { throw new Error("no store"); },
    );
    expect(renamed).toEqual([]);
  });
});
