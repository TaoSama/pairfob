import { ACCOUNT_HEADER, DEVICE_OWNER_HEADER } from "./constants.ts";
import { getDeviceOwner } from "./account-store.ts";
import { resolveIdentity } from "./account-auth.ts";

export interface DeviceAccess {
  /** The signed-in account behind the request, empty when anonymous. */
  account: string;
  /** The account that owns this daemon, empty when nobody has bound it. */
  owner: string;
  allowed: boolean;
}

/**
 * A bound daemon is reachable only by the account that owns it. An unbound one
 * is reachable by any signed-in account, because binding it is what the first
 * pairing does — but not anonymously: a device id is a guessable identifier,
 * not a credential, and a claim has to be attributable to someone to be worth
 * anything.
 */
export async function deviceAccess(
  db: D1Database,
  daemonId: string,
  req: Request,
  now: number,
): Promise<DeviceAccess> {
  const owner = await getDeviceOwner(db, daemonId);
  const identity = await resolveIdentity(db, req, now);
  const account = identity?.user.user_id ?? "";
  if (!owner) return { account, owner: "", allowed: account !== "" };
  return { account, owner: owner.user_id, allowed: account !== "" && account === owner.user_id };
}

/**
 * The room only ever receives requests the worker forwarded over the durable
 * object binding, so these headers carry the authorization decision inward
 * rather than being re-derived where D1 is not reachable.
 */
export function accessHeaders(req: Request, access: DeviceAccess): Request {
  const headers = new Headers(req.headers);
  headers.set(ACCOUNT_HEADER, access.account);
  headers.set(DEVICE_OWNER_HEADER, access.owner);
  return new Request(req, { headers });
}

export function readAccess(req: Request): { account: string; owner: string } {
  return {
    account: req.headers.get(ACCOUNT_HEADER) ?? "",
    owner: req.headers.get(DEVICE_OWNER_HEADER) ?? "",
  };
}
