/**
 * Passphrase gate input rules, mirrored byte-for-byte from the daemon's
 * `normalizePassword`. The passphrase is the SPAKE2+ `s` value: both sides must
 * derive the identical Argon2id record from it, so any divergence here fails
 * the handshake as "wrong password" with nothing left to debug.
 *
 * Unlike a pairing code the passphrase is not folded into an alphabet — the
 * operator typed these exact bytes. Only outer whitespace is trimmed, because a
 * trailing space from a paste or an on-screen keyboard is invisible and would
 * otherwise fail the handshake with no clue.
 */

/** A phone keyboard types this, so the floor leans on the gate throttle for entropy. */
export const MIN_PASSWORD_BYTES = 8;
/** The ceiling bounds the Argon2id input a hostile client can force. */
export const MAX_PASSWORD_BYTES = 128;
/**
 * Below this the passphrase is accepted but flagged as weak. Unlike the
 * one-shot pairing code, this credential is reused for every later pairing, so
 * an 8-byte passphrase stays guessable for as long as the gate is open. The
 * daemon sets the floor; this is only a nudge and never blocks a submit.
 */
export const WEAK_PASSWORD_BYTES = 12;

const encoder = new TextEncoder();

/** UTF-8 byte length, matching Go's `len(string)`. JS `.length` counts UTF-16 units. */
export function passwordByteLength(value: string): number {
  return encoder.encode(value).length;
}

/**
 * Go's `unicode.IsSpace`, which is what the daemon's `strings.TrimSpace` uses
 * (internal/daemon/gate.go). This set must stay byte-identical to it: whatever
 * one end trims and the other keeps produces a different Argon2id record from
 * the same typed characters, and the handshake then fails as "wrong password"
 * with nothing to debug.
 *
 * `String.prototype.trim` is not usable here. It strips U+FEFF, which Go keeps,
 * and its definition is tied to the JS spec rather than to Go's — so the set is
 * spelled out instead of inherited.
 */
const GO_SPACE = new Set([
  0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x20, // ASCII: \t \n \v \f \r and space
  0x85, 0xa0, // NEL, NBSP — the latter is what macOS Option+Space emits
  0x1680, // ogham space mark
  0x2000, 0x2001, 0x2002, 0x2003, 0x2004, 0x2005,
  0x2006, 0x2007, 0x2008, 0x2009, 0x200a, // en/em quad through hair space
  0x2028, 0x2029, // line and paragraph separators
  0x202f, 0x205f,
  0x3000, // ideographic space — emitted by CJK IMEs
]);

/** Trim over code points, so a trimmed astral character stays intact. */
function trimOuterSpace(value: string): string {
  const points = [...value];
  let start = 0;
  let end = points.length;
  while (start < end && GO_SPACE.has(points[start]!.codePointAt(0)!)) start += 1;
  while (end > start && GO_SPACE.has(points[end - 1]!.codePointAt(0)!)) end -= 1;
  return points.slice(start, end).join("");
}

/**
 * Go's `unicode.IsControl`: the Cc category, which is Latin-1 only. Control
 * characters are rejected rather than stripped — one in a passphrase is almost
 * always a paste accident, and silently dropping it would derive a record the
 * daemon never stored.
 */
function hasControlCharacter(value: string): boolean {
  for (const char of value) {
    const point = char.codePointAt(0)!;
    if (point <= 0x1f || (point >= 0x7f && point <= 0x9f)) return true;
  }
  return false;
}

/**
 * A lone surrogate cannot be typed; it only arrives from a corrupted paste.
 * `TextEncoder` silently substitutes U+FFFD for it, so the daemon would receive
 * — and store a record for — a passphrase the user never entered. Rejecting is
 * the only option that keeps the two ends honest.
 */
const LONE_SURROGATE = /\p{Surrogate}/u;

export type PasswordRejection =
  | "password_too_short"
  | "password_too_long"
  | "password_control_char"
  | "password_invalid";

export type PasswordCheck =
  | { ok: true; password: string; bytes: number }
  | { ok: false; error: PasswordRejection; bytes: number };

/**
 * Trim and validate a typed passphrase. The returned string is the exact value
 * to feed SPAKE2+; callers must never derive from the raw draft.
 */
export function normalizePassword(raw: string): PasswordCheck {
  const password = trimOuterSpace(raw);
  const bytes = passwordByteLength(password);
  if (LONE_SURROGATE.test(password)) return { ok: false, error: "password_invalid", bytes };
  if (bytes < MIN_PASSWORD_BYTES) return { ok: false, error: "password_too_short", bytes };
  if (bytes > MAX_PASSWORD_BYTES) return { ok: false, error: "password_too_long", bytes };
  if (hasControlCharacter(password)) return { ok: false, error: "password_control_char", bytes };
  return { ok: true, password, bytes };
}
