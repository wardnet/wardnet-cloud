import * as React from "react";
import type { MeView } from "../../api/contract";
import type { AccountState } from "../../account/spine";

export interface AccountContextValue {
  me: MeView;
  account: AccountState;
  tenantId: string;
}

const AccountContext = React.createContext<AccountContextValue | null>(null);

export function AccountProvider({
  value,
  children,
}: {
  value: AccountContextValue;
  children: React.ReactNode;
}) {
  return (
    <AccountContext.Provider value={value}>{children}</AccountContext.Provider>
  );
}

export function useAccount(): AccountContextValue {
  const ctx = React.useContext(AccountContext);
  if (!ctx) throw new Error("useAccount must be used within <AccountProvider>");
  return ctx;
}
