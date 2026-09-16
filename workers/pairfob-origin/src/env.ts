export interface Env {
  DB: D1Database;
  DAEMON_ROOM: DurableObjectNamespace;
  PAIRING_INDEX: DurableObjectNamespace;
  ASSETS?: Fetcher;
  METRICS?: AnalyticsEngineDataset;
  OPERATOR_TOKEN: string;
  /** Opens the very first account only. Kept apart from OPERATOR_TOKEN so the
   * relay operator's admin token is never a registration credential. */
  BOOTSTRAP_SERVICE_TOKEN: string;
  IP_HASH_PEPPER: string;
  BUILD?: string;
  P2P_OPEN?: string;
  INTENT_PAD_MS?: string;
}
