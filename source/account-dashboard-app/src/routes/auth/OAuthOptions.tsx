import { useNavigate } from "react-router-dom";
import { Divider, OAuthButton } from "@wardnet/ui";
import { oidcStartUrl } from "../../api/auth";
import { useSession } from "../../auth/AuthProvider";
import { MSW_ENABLED } from "../../config/env";
import s from "./auth.module.css";

/**
 * The two ghost OIDC provider buttons + the "or" divider. In production each
 * button is a full-page navigation to the backend OIDC start; under MSW (which
 * can't intercept a navigation) it runs the dev shortcut and resumes the
 * session in place.
 */
export function OAuthOptions() {
  const navigate = useNavigate();
  const { refresh } = useSession();

  async function handle(provider: "google" | "github") {
    if (MSW_ENABLED) {
      await fetch(`/v1/auth/oidc/${provider}/demo`, {
        method: "POST",
        credentials: "include",
      });
      if (await refresh()) navigate("/overview");
      return;
    }
    window.location.assign(oidcStartUrl(provider));
  }

  return (
    <>
      <div className={s.providers}>
        <OAuthButton provider="google" onClick={() => handle("google")} />
        <OAuthButton provider="github" onClick={() => handle("github")} />
      </div>
      <Divider>or</Divider>
    </>
  );
}
