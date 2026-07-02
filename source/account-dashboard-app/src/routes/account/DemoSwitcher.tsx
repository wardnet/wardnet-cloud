import * as React from "react";
import { useQueryClient } from "@tanstack/react-query";
import { Check, ChevronDown, FlaskConical } from "lucide-react";
import {
  Button,
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
  Text,
} from "@wardnet/ui";
import {
  getScenario,
  setScenario,
  subscribeScenario,
  type DataScenario,
  type Scenario,
  type SubScenario,
} from "../../mocks/scenario";

const SUB_OPTIONS: SubScenario[] = ["trial", "active", "grace", "cancelled"];
const DATA_OPTIONS: DataScenario[] = ["ready", "loading", "error", "empty"];

const cap = (v: string) => v.charAt(0).toUpperCase() + v.slice(1);

/**
 * Dev-only reviewer affordance: drives the MSW scenario (subscription state ×
 * data state). Stripped from production builds (gated by DEMO_ENABLED at the
 * call site). Changing a value invalidates all queries so the UI re-fetches.
 */
export function DemoSwitcher() {
  const qc = useQueryClient();
  const scenario = React.useSyncExternalStore<Scenario>(
    subscribeScenario,
    getScenario,
    getScenario,
  );

  function choose(patch: Partial<Scenario>) {
    setScenario(patch);
    void qc.invalidateQueries();
  }

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="ghost" size="sm" style={{ gap: 6 }}>
          <FlaskConical size={15} aria-hidden />
          <span>Demo</span>
          <ChevronDown size={14} aria-hidden />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" style={{ minWidth: 210 }}>
        <div style={{ padding: "4px 8px" }}>
          <Text variant="micro" color="ink-3">
            SUBSCRIPTION STATE
          </Text>
        </div>
        {SUB_OPTIONS.map((value) => (
          <DropdownMenuItem
            key={value}
            onSelect={() => choose({ subscription: value })}
          >
            <span style={{ flex: 1 }}>{cap(value)}</span>
            {scenario.subscription === value && <Check size={14} aria-hidden />}
          </DropdownMenuItem>
        ))}
        <DropdownMenuSeparator />
        <div style={{ padding: "4px 8px" }}>
          <Text variant="micro" color="ink-3">
            DATA STATE
          </Text>
        </div>
        {DATA_OPTIONS.map((value) => (
          <DropdownMenuItem key={value} onSelect={() => choose({ data: value })}>
            <span style={{ flex: 1 }}>{cap(value)}</span>
            {scenario.data === value && <Check size={14} aria-hidden />}
          </DropdownMenuItem>
        ))}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
