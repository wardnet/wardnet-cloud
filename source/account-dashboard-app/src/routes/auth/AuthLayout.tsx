import { Outlet } from "react-router-dom";
import { AuthFlowProvider } from "./AuthFlowContext";

/** Wraps the unauthenticated routes in the shared auth-flow state. */
export function AuthLayout() {
  return (
    <AuthFlowProvider>
      <Outlet />
    </AuthFlowProvider>
  );
}
