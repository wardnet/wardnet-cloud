import { Outlet } from "react-router-dom";
import { useMe } from "../../api/queries";
import { deriveAccountState } from "../../account/spine";
import { CardSkeleton, ErrorCard } from "../../components/feedback";
import { AccountProvider } from "./AccountContext";
import { TopBar } from "./TopBar";
import s from "./AccountLayout.module.css";

/**
 * Authenticated app shell. Fetches `GET /v1/me` once for the whole account
 * area, renders the sticky top bar, and provides the derived account state to
 * the tab routes via context.
 */
export function AccountLayout() {
  const meQuery = useMe();

  return (
    <>
      <TopBar me={meQuery.data} />
      <main className={s.page}>
        {meQuery.isPending ? (
          <div className={s.stack}>
            <CardSkeleton lines={2} />
            <CardSkeleton lines={3} />
          </div>
        ) : meQuery.isError ? (
          <ErrorCard
            message="Couldn't load your account."
            onRetry={() => void meQuery.refetch()}
          />
        ) : (
          <AccountProvider
            value={{
              me: meQuery.data,
              account: deriveAccountState(meQuery.data),
              tenantId: meQuery.data.tenant_id,
            }}
          >
            <Outlet />
          </AccountProvider>
        )}
      </main>
    </>
  );
}
