import { useDomain } from "../../shared/react/use-domain";
import { accountStore } from "./account-store";

/** React snapshot for the account domain. Owned by the account feature. */
export function useAccount() {
  return useDomain(accountStore);
}
