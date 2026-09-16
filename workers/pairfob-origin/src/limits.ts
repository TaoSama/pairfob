const buckets = new Map<string, number[]>();

export const LIMITS = {
  enrollIP: { n: 5, windowMs: 60 * 60 * 1000 },
  intentIP: { n: 10, windowMs: 10 * 60 * 1000 },
  sessionIP: { n: 60, windowMs: 60 * 1000 },
  eventsIP: { n: 60, windowMs: 60 * 1000 },
  // Covers reads such as the signed-in state poll as well as credential posts;
  // the brute-force ceiling is the D1 lockout ledger, not this bucket.
  authIP: { n: 120, windowMs: 10 * 60 * 1000 },
} as const;

export function allow(key: string, limit: number, windowMs: number, now: number): boolean {
  const hits = (buckets.get(key) ?? []).filter((t) => now - t < windowMs);
  if (hits.length >= limit) {
    buckets.set(key, hits);
    return false;
  }
  hits.push(now);
  buckets.set(key, hits);
  return true;
}

export function resetLimits(): void {
  buckets.clear();
}

export function allowEnrollIP(ip: string, now: number): boolean {
  return allow(`enroll-ip:${ip}`, LIMITS.enrollIP.n, LIMITS.enrollIP.windowMs, now);
}

export function allowIntentIP(ip: string, now: number): boolean {
  return allow(`intent-ip:${ip}`, LIMITS.intentIP.n, LIMITS.intentIP.windowMs, now);
}

export function allowSessionIP(ip: string, now: number): boolean {
  return allow(`session-ip:${ip}`, LIMITS.sessionIP.n, LIMITS.sessionIP.windowMs, now);
}

export function allowEventsIP(ip: string, now: number): boolean {
  return allow(`events-ip:${ip}`, LIMITS.eventsIP.n, LIMITS.eventsIP.windowMs, now);
}

export function allowAuthIP(ip: string, now: number): boolean {
  return allow(`auth-ip:${ip}`, LIMITS.authIP.n, LIMITS.authIP.windowMs, now);
}
