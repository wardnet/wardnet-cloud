import * as React from "react";
import { useQueryClient } from "@tanstack/react-query";
import { exchangeToken, logout as logoutApi } from "../api/auth";
import {
  setTokenRefresher,
  setUnauthorizedHandler,
  tokenStore,
} from "../api/client";

export type SessionStatus = "loading" | "authenticated" | "unauthenticated";

interface SessionContextValue {
  status: SessionStatus;
  /** Run the silent exchange (e.g. right after a password login sets the cookie). */
  refresh: () => Promise<boolean>;
  /** Mark the in-memory session authenticated with a freshly minted token. */
  signIn: (token: string) => void;
  /** Drop the session (server logout best-effort) and reset to logged-out. */
  signOut: () => Promise<void>;
}

const SessionContext = React.createContext<SessionContextValue | null>(null);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [status, setStatus] = React.useState<SessionStatus>("loading");
  const queryClient = useQueryClient();

  const refresh = React.useCallback(async () => {
    try {
      const { token } = await exchangeToken();
      tokenStore.set(token);
      setStatus("authenticated");
      return true;
    } catch {
      tokenStore.set(null);
      setStatus("unauthenticated");
      return false;
    }
  }, []);

  const signIn = React.useCallback((token: string) => {
    tokenStore.set(token);
    setStatus("authenticated");
  }, []);

  const signOut = React.useCallback(async () => {
    try {
      await logoutApi();
    } catch {
      // Best-effort: the local session is dropped regardless.
    }
    tokenStore.set(null);
    setStatus("unauthenticated");
    queryClient.clear();
  }, [queryClient]);

  // Silent resume on first load.
  React.useEffect(() => {
    void refresh();
  }, [refresh]);

  // A 401 first tries a silent re-exchange (`refresh`) + retry; only if that fails do
  // we drop to logged-out. This keeps the short-lived USER JWT expiring mid-session
  // from bouncing the user to the login screen.
  React.useEffect(() => {
    setTokenRefresher(refresh);
    setUnauthorizedHandler(() => {
      tokenStore.set(null);
      setStatus("unauthenticated");
    });
    return () => {
      setTokenRefresher(null);
      setUnauthorizedHandler(null);
    };
  }, [refresh]);

  const value = React.useMemo<SessionContextValue>(
    () => ({ status, refresh, signIn, signOut }),
    [status, refresh, signIn, signOut],
  );

  return (
    <SessionContext.Provider value={value}>{children}</SessionContext.Provider>
  );
}

export function useSession(): SessionContextValue {
  const ctx = React.useContext(SessionContext);
  if (!ctx) throw new Error("useSession must be used within <AuthProvider>");
  return ctx;
}
