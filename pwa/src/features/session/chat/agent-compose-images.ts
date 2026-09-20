/**
 * Image placeholder text edits for the agent compose field.
 *
 * The agent prompt protocol carries text only, so an attached image is
 * represented in the draft as a `[Image #N]` marker the way the underlying
 * coding agent already spells pasted images. These helpers are pure string
 * math over the draft: they own numbering, cursor-aware insertion, and marker
 * removal, so the React component and its tests share one source of truth.
 */

const IMAGE_MARKER = /\[Image #(\d+)\]/g;

/** Render the marker text for a given ordinal. */
export function imageMarker(ordinal: number): string {
  return `[Image #${ordinal}]`;
}

/**
 * Next ordinal is one past the largest marker already in the draft, so numbers
 * only ever grow. Removing an image never renumbers the survivors: a marker the
 * user typed by hand or copied elsewhere keeps pointing at the same thing.
 */
export function nextImageOrdinal(draft: string): number {
  let max = 0;
  for (const match of draft.matchAll(IMAGE_MARKER)) {
    const value = Number(match[1]);
    if (Number.isSafeInteger(value) && value > max) max = value;
  }
  return max + 1;
}

export type MarkerInsertion = {
  /** Draft with the marker spliced in at the caret. */
  text: string;
  /** The exact marker token inserted, for later precise removal. */
  marker: string;
  /** Caret position just past the inserted marker and its trailing space. */
  caret: number;
};

/**
 * Splice `[Image #N] ` in at the caret. A trailing space keeps the marker from
 * fusing with whatever the user types next; the caret lands past it so several
 * images inserted in a row read left to right.
 */
export function insertImageMarker(draft: string, caret: number, ordinal: number): MarkerInsertion {
  const at = Math.max(0, Math.min(caret, draft.length));
  const marker = imageMarker(ordinal);
  const chunk = `${marker} `;
  return {
    text: `${draft.slice(0, at)}${chunk}${draft.slice(at)}`,
    marker,
    caret: at + chunk.length,
  };
}

/**
 * Drop the first occurrence of an exact marker token and, if present, the one
 * trailing space we added with it. Only that token moves; every other character
 * the user wrote stays put.
 */
export function removeImageMarker(draft: string, marker: string): string {
  const at = draft.indexOf(marker);
  if (at === -1) return draft;
  let end = at + marker.length;
  if (draft[end] === " ") end += 1;
  return draft.slice(0, at) + draft.slice(end);
}
