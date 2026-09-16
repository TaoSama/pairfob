import {
  DEFAULT_TTL_MS,
  HELLO_GRACE_MS,
  LOC_MINT_TRIES,
  MAX_PAIRING,
  MAX_TTL_S,
  MIN_TTL_S,
  PAIR_REF_RE,
  PROTOCOL,
} from "../constants.ts";
import { bytesToHex, isZeroRoute, newRouteId, routeHex } from "../crypto.ts";
import { mintLoc } from "../crockford.ts";
import { Typ, type Frame } from "../envelope.ts";
import { parseJSONObject, reject, sendErr, sendJSON } from "../frames.ts";
import { armPairFirst, clearKindRef, schedule } from "./alarms.ts";
import { ownerMismatch } from "./attachment.ts";
import type { RoomCore } from "./core.ts";
import type { RoomSocket } from "./types.ts";

export async function handlePairOpen(room: RoomCore, ws: RoomSocket, frame: Frame): Promise<void> {
  await room.withPairingLock(() => handlePairOpenLocked(room, ws, frame));
}

async function handlePairOpenLocked(room: RoomCore, ws: RoomSocket, frame: Frame): Promise<void> {
  if (!isZeroRoute(frame.routeId)) {
    reject(ws, "bad_token", "PAIR_OPEN route_id must be zero");
    return;
  }
  const req = parseJSONObject(frame.payload);
  const daemonId = typeof req?.daemon_id === "string" ? req.daemon_id : "";
  const pairRef = typeof req?.pair_ref === "string" ? req.pair_ref : "";
  const ttlS = typeof req?.ttl_s === "number" ? req.ttl_s : 180;
  if (!req || req.v !== PROTOCOL || (req.op !== undefined && req.op !== "" && req.op !== "CreatePairing")) {
    sendErr(ws, "bad_token", "invalid pairing slot");
    return;
  }
  if (!PAIR_REF_RE.test(pairRef)) {
    sendErr(ws, "bad_token", "invalid pair_ref");
    return;
  }
  if (room.daemon !== ws) {
    sendErr(ws, "unbound", "no daemon");
    return;
  }
  if (daemonId !== room.daemonId) {
    sendErr(ws, "unbound", "daemon_id does not match websocket");
    return;
  }
  const ttlMs = ttlS >= MIN_TTL_S && ttlS <= MAX_TTL_S ? ttlS * 1000 : DEFAULT_TTL_MS;
  const deadline = room.now() + ttlMs;
  const idx = room.index();
  if (!idx) {
    sendErr(ws, "index_unavailable", "pairing index missing", { pairRef });
    return;
  }
  const existing = room.store.loadSlot();
  if (existing && existing.pair_ref === pairRef) {
    const previousDeadline = existing.deadline;
    try {
      existing.deadline = deadline;
      room.store.putSlot(existing);
      await schedule(room.store, "pair_ttl", pairRef, deadline);
    } catch {
      existing.deadline = previousDeadline;
      room.store.putSlot(existing);
      sendErr(ws, "index_unavailable", "pairing slot refresh failed", { pairRef });
      return;
    }
    const ins = await idx.insert({
      pair_loc: existing.pair_loc,
      daemon_id: room.daemonId,
      pair_ref: pairRef,
      exp: deadline,
    });
    if (ins !== "ok") {
      existing.deadline = previousDeadline;
      room.store.putSlot(existing);
      sendErr(ws, "index_unavailable", "pairing index refresh failed", { pairRef });
      return;
    }
    if (room.daemon !== ws) {
      await idx.remove(existing.pair_loc, { daemon_id: room.daemonId, pair_ref: pairRef });
      return;
    }
    sendJSON(ws, Typ.PAIR_OPEN, frame.routeId, {
      v: PROTOCOL,
      op: "CreatePairing",
      ok: true,
      pair_ref: pairRef,
      pair_loc: existing.pair_loc,
      ttl_s: Math.round(ttlMs / 1000),
    });
    return;
  }
  for (let i = 0; i < LOC_MINT_TRIES; i++) {
    const loc = mintLoc((n) => room.random(n));
    try {
      room.store.putSlot({ pair_ref: pairRef, pair_loc: loc, deadline });
      await schedule(room.store, "pair_ttl", pairRef, deadline);
    } catch {
      if (existing) room.store.putSlot(existing);
      else room.store.deleteSlot();
      sendErr(ws, "index_unavailable", "pairing slot commit failed", { pairRef });
      return;
    }
    const ins = await idx.insert({ pair_loc: loc, daemon_id: room.daemonId, pair_ref: pairRef, exp: deadline });
    if (ins === "ok") {
      if (room.daemon !== ws) {
        await idx.remove(loc, { daemon_id: room.daemonId, pair_ref: pairRef });
        if (existing) room.store.putSlot(existing);
        else room.store.deleteSlot();
        return;
      }
      if (existing) {
        for (const c of room.sockets()) {
          const a = room.att(c);
          if (a?.kind === "pairing") {
            room.closeBind(c, "pairing_replaced", "another computer opened pairing");
          }
        }
        sendErr(ws, "pairing_replaced", "another computer opened pairing", { pairRef: existing.pair_ref });
        await idx.remove(existing.pair_loc, { daemon_id: room.daemonId, pair_ref: existing.pair_ref });
      }
      sendJSON(ws, Typ.PAIR_OPEN, frame.routeId, {
        v: PROTOCOL,
        op: "CreatePairing",
        ok: true,
        pair_ref: pairRef,
        pair_loc: loc,
        ttl_s: Math.round(ttlMs / 1000),
      });
      return;
    }
    if (existing) room.store.putSlot(existing);
    else room.store.deleteSlot();
    if (ins === "fail") {
      sendErr(ws, "index_unavailable", "pairing index insert failed", { pairRef });
      return;
    }
  }
  sendErr(ws, "index_unavailable", "pairing index insert failed", { pairRef });
}

export async function handlePairClose(room: RoomCore, ws: RoomSocket, frame: Frame): Promise<void> {
  await room.withPairingLock(() => handlePairCloseLocked(room, ws, frame));
}

async function handlePairCloseLocked(room: RoomCore, ws: RoomSocket, frame: Frame): Promise<void> {
  if (!isZeroRoute(frame.routeId)) {
    sendErr(ws, "bad_token", "invalid pair_ref");
    return;
  }
  const req = parseJSONObject(frame.payload);
  const pairRef = typeof req?.pair_ref === "string" ? req.pair_ref : "";
  if (!req || req.v !== PROTOCOL || !PAIR_REF_RE.test(pairRef)) {
    sendErr(ws, "bad_token", "invalid pair_ref");
    return;
  }
  if (room.daemon !== ws) {
    sendErr(ws, "unbound", "no daemon");
    return;
  }
  const slot = room.store.loadSlot();
  if (slot && slot.pair_ref === pairRef) {
    for (const c of room.sockets()) {
      const a = room.att(c);
      if (a?.kind === "pairing" && a.pair_ref === pairRef) room.closeBind(c, "unpaired", "pairing closed");
    }
    await room.index()?.remove(slot.pair_loc, { daemon_id: room.daemonId, pair_ref: slot.pair_ref });
    room.store.deleteSlot();
    await clearKindRef(room.store, "pair_ttl", pairRef);
  }
}

export async function handlePairAttach(room: RoomCore, ws: RoomSocket, frame: Frame): Promise<void> {
  if (!isZeroRoute(frame.routeId)) {
    reject(ws, "bad_token", "invalid PAIR_ATTACH payload");
    return;
  }
  const req = parseJSONObject(frame.payload);
  const pairRef = typeof req?.pair_ref === "string" ? req.pair_ref : "";
  if (!req || req.v !== PROTOCOL) {
    reject(ws, "bad_token", "invalid PAIR_ATTACH payload");
    return;
  }
  if (!PAIR_REF_RE.test(pairRef)) {
    sendErr(ws, "bad_token", "invalid pair_ref");
    return;
  }
  const att = room.att(ws);
  if (!att || att.role !== "phone") {
    reject(ws, "unbound", "PAIR_ATTACH on non-phone websocket");
    return;
  }
  if (ownerMismatch(att)) {
    sendErr(ws, "forbidden", "device belongs to another account");
    ws.close(1000, "forbidden");
    return;
  }
  if (!att.hello_at_ms || room.now() - att.hello_at_ms > HELLO_GRACE_MS) {
    sendErr(ws, "unbound", "PAIR_ATTACH after HELLO timeout");
    ws.close(1000, "unbound");
    return;
  }
  if (att.mode === "session" || att.kind === "resumehello" || att.kind === "established") {
    sendErr(ws, "wrong_ws", "PAIR_ATTACH on SessionWS");
    return;
  }
  if (att.kind === "pairing" || att.mode === "pairing") {
    sendErr(ws, "wrong_ws", "PairingWS already attached");
    return;
  }
  if (!room.daemon) {
    sendErr(ws, "daemon_offline", "no daemon");
    return;
  }
  const slot = room.store.loadSlot();
  if (!slot || slot.deadline <= room.now() || slot.pair_ref !== pairRef) {
    sendErr(ws, "unpaired", "no slot");
    return;
  }
  const { pairing } = room.countKinds();
  if (pairing >= MAX_PAIRING) {
    sendErr(ws, "pair_busy", "pairing slot already attached");
    return;
  }
  // Refuse a fresh pairing route while the room is cooling down. Each attach is
  // one shot at the passphrase, so gating here is what makes the backoff bite:
  // without it a guesser just reconnects for an unthrottled attempt.
  const gate = room.gateCheck();
  if (!gate.allowed) {
    sendErr(ws, "rate_limited", "too many failed pairing attempts", {
      retryAfterMs: gate.retryAfterMs,
    });
    return;
  }
  // Charge the attempt on attach rather than waiting for the daemon's
  // bad_pair_code. The relay only ever learns of a failure if the guesser
  // stays connected long enough to be told, and it has no reason to: the
  // daemon's SPAKE2+ answer is checkable offline, so an attacker reads it and
  // drops the socket. Measured before this line existed: 25 consecutive
  // attach-then-hang-up probes were all answered and the ledger held 0 rows.
  //
  // The charge is never refunded here, and deliberately so. Refund eligibility
  // has to be earned by a verified confirm, which is the only thing that tells
  // an owner from a guesser — and the relay cannot see it, because the confirm
  // rides inside an AEAD payload it must never open. Refunding on any signal
  // the relay *can* see (a second pairing frame, say) would hand an attacker a
  // free cooldown reset for the price of one junk frame. The daemon holds the
  // key and does the refund there, after the proof verifies
  // (internal/daemon/pairing.go refundGateAttemptLocked). A room therefore
  // counts a successful login as one failure, which only makes this coarse
  // per-room window more conservative; the owner's protection against lockout
  // lives on the daemon side.
  room.noteGateAttempt(false);

  const rid = newRouteId(room.random.bind(room));
  const hex = routeHex(rid);
  const now = room.now();
  att.mode = "pairing";
  att.kind = "pairing";
  att.route_id = hex;
  att.pair_ref = pairRef;
  att.pair_frames = 0;
  att.created_ms = now;
  room.writeAtt(ws, att);
  room.store.upsertBind({ route_id: hex, kind: "pairing", created_at: now, pair_ref: pairRef });
  room.noteBind("pairing");
  await armPairFirst(room, hex, now);

  const attempt = "at_" + bytesToHex(room.random(8));
  const body = {
    v: PROTOCOL,
    attempt_id: attempt,
    route_id: hex,
    daemon_id: room.daemonId,
    pair_ref: pairRef,
  };
  sendJSON(ws, Typ.PAIR_ATTACHED, rid, body);
  sendJSON(room.daemon, Typ.PAIR_ATTACHED, rid, body);
}
