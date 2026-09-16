/**
 * The seam between a completed pairing and the account that should own it.
 *
 * Pairing is a closed feature: it talks to the relay, the credential database
 * and its own domain, and it deliberately cannot reach a page. But a machine
 * paired while signed in has to be claimed for that account, and the code that
 * knows how to claim it lives on the account page, above that line.
 *
 * So pairing announces, and whoever is interested listens. The default is
 * nobody: a build with no account plane, or a page that has not mounted one,
 * leaves the seam empty and pairing behaves exactly as it always has. That is
 * the property worth keeping — binding to an account is an addition to pairing,
 * never a precondition for it.
 *
 * The claim is deliberately not awaited by the announcer. It waits on a person
 * walking to a computer and confirming, which can take minutes, and pairing must
 * not hold its own completion open for that.
 */
export type PairedDeviceClaimer = (daemonId: string, label: string | null) => void;

let claimer: PairedDeviceClaimer | null = null;

/** Install the claimer, or clear it when the page that owned it goes away. */
export function registerPairedDeviceClaimer(next: PairedDeviceClaimer | null): void {
  claimer = next;
}

/** The installed claimer, if any. Fixtures inspect the seam before injecting. */
export function pairedDeviceClaimer(): PairedDeviceClaimer | null {
  return claimer;
}

/** Announce a machine this browser has just paired with. */
export function notifyDevicePaired(daemonId: string, label: string | null): void {
  claimer?.(daemonId, label);
}
