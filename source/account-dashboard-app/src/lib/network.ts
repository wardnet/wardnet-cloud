import type { ProvisioningState } from "../api/contract";

interface NetworkStatusDisplay {
  label: string;
  variant: "ok" | "info" | "down";
}

// provisioning_state → pill. No "Degraded"/health signal exists — see issue #19.
const NETWORK_STATUS: Record<ProvisioningState, NetworkStatusDisplay> = {
  active: { label: "Online", variant: "ok" },
  provisioning: { label: "Provisioning", variant: "info" },
  deprovisioning: { label: "Deprovisioning", variant: "down" },
};

export function networkStatus(state: ProvisioningState): NetworkStatusDisplay {
  return NETWORK_STATUS[state];
}
