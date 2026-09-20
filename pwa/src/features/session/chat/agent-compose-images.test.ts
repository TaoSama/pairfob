import { describe, expect, test } from "bun:test";
import {
  imageMarker,
  insertImageMarker,
  nextImageOrdinal,
  removeImageMarker,
} from "./agent-compose-images";

describe("agent compose image markers", () => {
  test("numbering starts at 1 and grows past the largest existing marker", () => {
    expect(nextImageOrdinal("")).toBe(1);
    expect(nextImageOrdinal("look [Image #1] here")).toBe(2);
    expect(nextImageOrdinal("[Image #3] then [Image #1]")).toBe(4);
  });

  test("removing an image never renumbers the survivors", () => {
    const draft = "[Image #1] [Image #2] [Image #3]";
    const afterMiddle = removeImageMarker(draft, imageMarker(2));
    expect(afterMiddle).toBe("[Image #1] [Image #3]");
    // The next insert still climbs past the highest number left behind.
    expect(nextImageOrdinal(afterMiddle)).toBe(4);
  });

  test("insertion splices at the caret and returns the caret past the marker", () => {
    const before = "hello world";
    const caret = 5; // between "hello" and " world"
    const result = insertImageMarker(before, caret, 1);
    expect(result.text).toBe("hello[Image #1]  world");
    expect(result.marker).toBe("[Image #1]");
    expect(before.slice(0, caret) + result.text.slice(caret, result.caret)).toBe("hello[Image #1] ");
  });

  test("multiple caret insertions read left to right", () => {
    let draft = "start end";
    const first = insertImageMarker(draft, 6, nextImageOrdinal(draft)); // before "end"
    draft = first.text;
    const second = insertImageMarker(draft, first.caret, nextImageOrdinal(draft));
    expect(second.text).toBe("start [Image #1] [Image #2] end");
  });

  test("insertion caret clamps to the draft bounds", () => {
    const result = insertImageMarker("abc", 99, 1);
    expect(result.text).toBe("abc[Image #1] ");
    expect(result.caret).toBe(result.text.length);
  });

  test("removal drops the marker and its trailing space, leaving other text intact", () => {
    expect(removeImageMarker("a [Image #1] b", "[Image #1]")).toBe("a b");
    // No trailing space to eat when the marker ends the draft.
    expect(removeImageMarker("tail [Image #2]", "[Image #2]")).toBe("tail ");
    // An unknown marker is a no-op.
    expect(removeImageMarker("keep me", "[Image #9]")).toBe("keep me");
  });
});
