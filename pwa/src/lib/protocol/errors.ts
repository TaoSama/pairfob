import type { ConnectionDetails } from "./connection-diagnostics.ts";
export class ProtocolError extends Error {
  constructor(
    public readonly code: string,
    message?: string,
    public readonly diagnostics?: ConnectionDetails,
    /**
     * The refusal's own fields, verbatim from the origin's error object.
     *
     * A code alone cannot say how many tries are left or which version the
     * origin holds, and a caller that has to explain the refusal to a person
     * needs those numbers. Kept opaque here: this layer does not know which
     * route contributes which field, so it validates none of them and every
     * reader narrows what it actually uses.
     */
    public readonly detail?: Record<string, unknown>,
  ) {
    super(message || code);
    this.name = "ProtocolError";
  }
}
