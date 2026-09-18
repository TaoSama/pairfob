export const PROTOCOL = 2;
export const SUBPROTOCOL = "pairfob.v2";
export const BUILD_DEFAULT = "dev";

export const GRANT_ID_RE = /^g_[0-9a-f]{16}$/;
export const DAEMON_ID_RE = /^d_[0-9a-f]{20}$/;
export const RECONNECT_TOKEN_RE = /^rt_[0-9a-f]{32}$/;
export const PAIR_REF_RE = /^[0-9a-f]{32}$/;
export const TICKET_RE = /^[0-9a-f]{32}$/;

export const HELLO_GRACE_MS = 5_000;
export const RESUME_MS = 15_000;
export const PAIR_FIRST_MS = 15_000;
export const PAIR_CONFIRM_MS = 30_000;
export const TICKET_MS = 15_000;
export const DEFAULT_TTL_MS = 180_000;
export const MIN_TTL_S = 60;
export const MAX_TTL_S = 300;
export const MAX_ESTABLISHED = 10;
export const MAX_RESUME = 2;
export const MAX_PENDING_HELLO = 8;
// Concurrent PairingWS binds per room. This is 1 because the daemon holds a
// single pairing slot, not because the relay cannot route more: a second
// PAIR_ATTACHED overwrites `pair.routeID` and resets the SPAKE2+ verifier,
// silently destroying the first phone's handshake. Refusing here turns that
// into an explicit `pair_busy` the phone can render and retry.
//
// Raising this requires the daemon to key pairing state per route first;
// until then a larger value trades a clear error for silent cross-talk.
export const MAX_PAIRING = 1;

// The daemon's verdict on a pairing proof. It is the only failure signal the
// relay can act on: the SPAKE2+ exchange happens end-to-end inside opaque FWD
// payloads, so this error code is all the relay ever learns about a guess.
export const GATE_FAILURE_CODE = "bad_pair_code";
export const FWD_FLUSH_BYTES = 65_536;
export const LOC_MINT_TRIES = 8;

export const OPEN_ENROLL_MAX_DAEMONS = 1;
export const SELF_GRANT_WINDOW_MS = 24 * 60 * 60 * 1000;
export const SELF_GRANT_PER_IP = 3;

export const USER_ID_RE = /^u_[0-9a-f]{16}$/;
export const USERNAME_RE = /^[a-z0-9][a-z0-9._-]{2,31}$/;
export const INVITE_CODE_RE = /^[A-Z]{4}$/;
export const ADMIN_USERNAME = "admin";
export const ROLE_ADMIN = "admin";
export const ROLE_MEMBER = "member";
export const SESSION_COOKIE = "pairfob_session";
export const SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000;
export const PASSWORD_MIN = 8;
export const PASSWORD_MAX = 128;
export const DEVICE_LABEL_MAX = 64;
export const AUTH_LOCKOUT_STRIKES = 3;
export const AUTH_LOCKOUT_MS = 60 * 60 * 1000;

/**
 * Signing in gets more room than an invite code or a bootstrap token. Someone
 * retyping a password they already own is not a brute-force source, while a
 * wrong invite code or service token can only have been guessed.
 */
export const LOGIN_LOCKOUT_STRIKES = 5;
export const INVITE_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
export const INVITE_CODE_LEN = 4;

/**
 * The invite code is four letters by product requirement, so a single source
 * budget cannot cover a spread-out guess. This second budget counts every wrong
 * code regardless of origin and suspends the code until it is rotated.
 */
export const INVITE_GLOBAL_STRIKES = 20;

export const CLAIM_PROOF_RE = /^cp_[0-9a-f]{32}$/;
export const CLAIM_PROOF_TTL_MS = 10 * 60 * 1000;

/**
 * The vault is an opaque blob the relay stores and never opens. The ceiling is
 * on the encoded ciphertext in bytes, because a multi-byte character would let
 * a length check in code units admit several times the intended payload.
 */
export const VAULT_MAX_BYTES = 65_536;
export const VAULT_KDF_MAX = 128;
export const VAULT_NONCE_MAX = 128;
export const BASE64_RE = /^[A-Za-z0-9+/]+={0,2}$/;

export const ACCOUNT_HEADER = "X-Pairfob-Account";
export const DEVICE_OWNER_HEADER = "X-Pairfob-Device-Owner";

export const CSP =
  "default-src 'self'; connect-src 'self'; img-src 'self' data: blob:; media-src blob:; style-src 'self' https://fonts.googleapis.com 'sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=' 'sha256-JVKkopR5uGguAsHA+8LKNHePLgO6ntgrlxTcOIvoM4w='; font-src 'self' https://fonts.gstatic.com; script-src 'self' 'wasm-unsafe-eval'; worker-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'; object-src 'none'; upgrade-insecure-requests;";

/** The marketing page has no Wasm and therefore gets the stricter script policy. */
export const CSP_SITE =
  "default-src 'self'; connect-src 'self'; img-src 'self' data:; style-src 'self' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; script-src 'self'; worker-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'; object-src 'none'; upgrade-insecure-requests;";
