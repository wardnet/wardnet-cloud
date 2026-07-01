import * as React from "react";

export type AuthFlow = "signup" | "reset";

interface AuthFlowState {
  /** Email entered at register/forgot, carried into confirm + set-password. */
  email: string;
  /** Verified code, carried from confirm into set-password. */
  code: string;
  /** Which flow the confirm/set-password screens are serving. */
  flow: AuthFlow;
  /** The code the backend returned at issuance, when it is NOT delivering email
   *  (dev no-op sender). `null` means it was emailed; the Confirm screen surfaces
   *  a non-null value so a no-email dev backend is still usable. */
  sentCode: string | null;
  set: (patch: Partial<Omit<AuthFlowState, "set">>) => void;
}

const AuthFlowContext = React.createContext<AuthFlowState | null>(null);

export function AuthFlowProvider({ children }: { children: React.ReactNode }) {
  const [state, setState] = React.useState({
    email: "",
    code: "",
    flow: "signup" as AuthFlow,
    sentCode: null as string | null,
  });
  const set = React.useCallback(
    (patch: Partial<Omit<AuthFlowState, "set">>) =>
      setState((prev) => ({ ...prev, ...patch })),
    [],
  );
  const value = React.useMemo<AuthFlowState>(
    () => ({ ...state, set }),
    [state, set],
  );
  return (
    <AuthFlowContext.Provider value={value}>
      {children}
    </AuthFlowContext.Provider>
  );
}

export function useAuthFlow(): AuthFlowState {
  const ctx = React.useContext(AuthFlowContext);
  if (!ctx) throw new Error("useAuthFlow must be used within <AuthFlowProvider>");
  return ctx;
}
