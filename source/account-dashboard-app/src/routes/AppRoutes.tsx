import { Navigate, Outlet, Route, Routes } from "react-router-dom";
import { useSession } from "../auth/AuthProvider";
import { AuthLayout } from "./auth/AuthLayout";
import { SignIn } from "./auth/SignIn";
import { Register } from "./auth/Register";
import { Forgot } from "./auth/Forgot";
import { Confirm } from "./auth/Confirm";
import { SetPassword } from "./auth/SetPassword";
import { AccountLayout } from "./account/AccountLayout";
import { Overview } from "./account/Overview";
import { Subscription } from "./account/Subscription";
import { Security } from "./account/Security";

function FullScreenLoading() {
  return (
    <div
      style={{
        minHeight: "100vh",
        display: "grid",
        placeItems: "center",
        background: "var(--bg)",
        color: "var(--ink-3)",
      }}
    >
      Loading…
    </div>
  );
}

/** Gate the authenticated area: bounce logged-out users to sign-in. */
function RequireAuth() {
  const { status } = useSession();
  if (status === "loading") return <FullScreenLoading />;
  if (status === "unauthenticated") return <Navigate to="/signin" replace />;
  return <Outlet />;
}

export function AppRoutes() {
  return (
    <Routes>
      <Route element={<AuthLayout />}>
        <Route path="/signin" element={<SignIn />} />
        <Route path="/register" element={<Register />} />
        <Route path="/forgot" element={<Forgot />} />
        <Route path="/confirm" element={<Confirm />} />
        <Route path="/set-password" element={<SetPassword />} />
      </Route>

      <Route element={<RequireAuth />}>
        <Route element={<AccountLayout />}>
          <Route path="/overview" element={<Overview />} />
          <Route path="/subscription" element={<Subscription />} />
          <Route path="/security" element={<Security />} />
        </Route>
      </Route>

      <Route path="/" element={<Navigate to="/overview" replace />} />
      <Route path="*" element={<Navigate to="/overview" replace />} />
    </Routes>
  );
}
