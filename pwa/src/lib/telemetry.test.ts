import { afterEach, describe, expect, test } from "bun:test";
import {
  encodeBeaconBody,
  flushTelemetry,
  resetTelemetry,
  sanitizeBeaconEvent,
  setTelemetrySender,
  track,
} from "./telemetry.ts";

afterEach(() => {
  resetTelemetry();
  // Not `null`: the sender is module state shared by the whole suite, and the
  // default one reaches the network. Restoring it here made later files post
  // real telemetry, whose in-flight request then failed whichever test happened
  // to tear its DOM down next.
  setTelemetrySender(() => {});
});

describe("PWA telemetry", () => {
  test("only allowlisted names and token-shaped fields survive", () => {
    expect(sanitizeBeaconEvent("pwa_boot", { result: "ok", extra: "connect" })).toEqual({
      name: "pwa_boot",
      result: "ok",
      extra: "connect",
    });
    expect(sanitizeBeaconEvent("enroll", { result: "ok" })).toBeNull();
    expect(sanitizeBeaconEvent("pwa_boot", { result: "jg_" + "aa".repeat(16) })).toEqual({ name: "pwa_boot" });
    expect(sanitizeBeaconEvent("pwa_pairing_start", { extra: "qr code" })).toEqual({ name: "pwa_pairing_start" });
    expect(sanitizeBeaconEvent("pwa_agent_trace", { result: "content", extra: "lt_100ms" })).toEqual({
      name: "pwa_agent_trace",
      result: "content",
      extra: "lt_100ms",
    });
    expect(sanitizeBeaconEvent("pwa_p2p", { result: "failed", extra: "ice_timeout" })).toEqual({
      name: "pwa_p2p",
      result: "failed",
      extra: "ice_timeout",
    });
    expect(encodeBeaconBody([{ name: "pwa_live" }])).toBe(JSON.stringify({ v: 2, events: [{ name: "pwa_live" }] }));
  });

  test("flushes a first-party JSON beacon without pairing secrets", () => {
    const bodies: string[] = [];
    setTelemetrySender((body) => bodies.push(body));
    track("pwa_pairing_start", { extra: "manual" });
    track("pwa_pairing_result", { result: "unpaired", extra: "manual" });
    track("enroll", { result: "ok" });
    flushTelemetry();
    expect(bodies).toHaveLength(1);
    const parsed = JSON.parse(bodies[0]) as { v: number; events: Array<{ name: string; result?: string; extra?: string }> };
    expect(parsed).toEqual({
      v: 2,
      events: [
        { name: "pwa_pairing_start", extra: "manual" },
        { name: "pwa_pairing_result", result: "unpaired", extra: "manual" },
      ],
    });
    expect(bodies[0]).not.toContain("jg_");
    expect(bodies[0]).not.toContain("pair_ticket");
    expect(bodies[0]).not.toContain("d_");
  });
});
