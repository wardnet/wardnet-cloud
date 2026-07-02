import * as React from "react";
import { useNavigate } from "react-router-dom";
import { Github, KeyRound, Mail } from "lucide-react";
import {
  Banner,
  Button,
  Card,
  CardContent,
  CardHeader,
  CardSubtitle,
  CardTitle,
  CodeInput,
  Field,
  Form,
  Heading,
  Input,
  Pill,
  Text,
  useFormContext,
  Validator,
} from "@wardnet/ui";
import { useQueryClient } from "@tanstack/react-query";
import {
  oidcStartUrl,
  requestVerificationCode,
  setPassword as apiSetPassword,
} from "../../api/auth";
import {
  queryKeys,
  useDisconnectIdentity,
  useIdentities,
  useSignOutAll,
} from "../../api/queries";
import { useSession } from "../../auth/AuthProvider";
import type { ConnectedIdentityView, IdentityProvider } from "../../api/contract";
import { QueryStates } from "../../components/feedback";
import { passwordMatchError, passwordMinError } from "../../lib/validation";
import { useAccount } from "./AccountContext";
import layout from "./AccountLayout.module.css";
import s from "./Security.module.css";

const PROVIDERS: {
  id: IdentityProvider;
  label: string;
  icon: React.ReactNode;
  linkable: boolean;
}[] = [
  { id: "google", label: "Google", icon: <Mail size={16} aria-hidden />, linkable: true },
  { id: "github", label: "GitHub", icon: <Github size={16} aria-hidden />, linkable: true },
  {
    id: "password",
    label: "Email & password",
    icon: <KeyRound size={16} aria-hidden />,
    linkable: false,
  },
];

function ConnectedMethods({
  identities,
}: {
  identities: ConnectedIdentityView[];
}) {
  const disconnect = useDisconnectIdentity();
  const [notice, setNotice] = React.useState<string | null>(null);
  const byProvider = new Map(identities.map((i) => [i.provider, i]));
  const connectedCount = identities.length;

  function onDisconnect(provider: IdentityProvider, isOnlyMethod: boolean) {
    setNotice(null);
    if (isOnlyMethod) {
      // Don't bother the backend — explain why instead of silently doing nothing.
      // Tailor the suggestion to what they don't already have: if password is the
      // last method, suggesting "set a password" would be nonsensical.
      setNotice(
        provider === "password"
          ? "You can't disconnect your only sign-in method. Connect Google or GitHub first."
          : "You can't disconnect your only sign-in method. Set a password or connect another provider first.",
      );
      return;
    }
    disconnect.mutate(provider, {
      onError: () =>
        setNotice("Couldn't disconnect that method. Please try again."),
    });
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Connected sign-in methods</CardTitle>
        <CardSubtitle>
          Link a provider for one-tap sign in. At least one method must stay
          connected.
        </CardSubtitle>
      </CardHeader>
      <CardContent>
        {PROVIDERS.map((p) => {
          const identity = byProvider.get(p.id);
          const isOnlyMethod = identity != null && connectedCount <= 1;
          return (
            <div key={p.id} className={s.methodRow}>
              <span className={s.methodIcon}>{p.icon}</span>
              <div className={s.methodMeta}>
                <Text variant="body-strong">{p.label}</Text>
                <Text variant="caption" color="ink-3">
                  {identity ? identity.label : "Not connected"}
                </Text>
              </div>
              {identity ? (
                <>
                  <Pill variant="ok">Connected</Pill>
                  <Button
                    variant="ghost"
                    size="sm"
                    disabled={disconnect.isPending}
                    onClick={() => onDisconnect(p.id, isOnlyMethod)}
                  >
                    Disconnect
                  </Button>
                </>
              ) : (
                p.linkable && (
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() =>
                      window.location.assign(oidcStartUrl(p.id as "google" | "github", "link"))
                    }
                  >
                    Connect
                  </Button>
                )
              )}
            </div>
          );
        })}
        {notice && (
          <Text variant="caption" color="danger" role="alert">
            {notice}
          </Text>
        )}
      </CardContent>
    </Card>
  );
}

/** The 6-box code input, surfacing its `<Validator name="code">` error from the
 *  parent `<Form>` context (CodeInput is not a `<Field>`). */
function CodeField({
  value,
  onChange,
}: {
  value: string;
  onChange: (v: string) => void;
}) {
  const ctx = useFormContext();
  const errors = ctx?.errors.code ?? [];
  return (
    <div className={s.codeWrap}>
      <CodeInput
        value={value}
        onChange={onChange}
        mode="alphanumeric"
        error={errors.length > 0}
        aria-label="Verification character"
      />
      {errors.length > 0 && (
        <Text variant="caption" color="danger">
          {errors[0]}
        </Text>
      )}
    </div>
  );
}

/**
 * Set (for OIDC-only accounts) or change the email/password credential. Both are
 * the same code-exchange flow: a password is only ever set behind a fresh
 * `password_change` email-proof code — so a hijacked, already-signed-in session
 * can't silently add a password and lock the owner out. The server revokes all
 * sessions and rotates a fresh one onto this browser, so the user stays signed in;
 * we just refresh the connected-methods list so the card reflects the new state.
 */
function PasswordCard({
  hasPassword,
  email,
}: {
  hasPassword: boolean;
  email: string;
}) {
  const qc = useQueryClient();
  const [step, setStep] = React.useState<"idle" | "code">("idle");
  const [sentCode, setSentCode] = React.useState<string | null>(null);
  const [code, setCode] = React.useState("");
  const [password, setPassword] = React.useState("");
  const [confirm, setConfirm] = React.useState("");
  const [error, setError] = React.useState<string | null>(null);
  const [busy, setBusy] = React.useState(false);
  const [done, setDone] = React.useState(false);

  const action = hasPassword ? "Change password" : "Set password";

  async function sendCode() {
    setError(null);
    setDone(false);
    setBusy(true);
    try {
      const resp = await requestVerificationCode({
        email,
        purpose: "password_change",
      });
      setSentCode(resp.code ?? null);
      setStep("code");
    } catch {
      setError("Couldn't send the code. Try again.");
    } finally {
      setBusy(false);
    }
  }

  async function onSubmit() {
    setError(null);
    setBusy(true);
    try {
      await apiSetPassword({ code, password });
      // The server rotated this browser onto a fresh session — stay put. Reset the
      // form and refresh identities so the card reflects the now-set password.
      setStep("idle");
      setCode("");
      setPassword("");
      setConfirm("");
      setSentCode(null);
      setDone(true);
      await qc.invalidateQueries({ queryKey: queryKeys.identities });
    } catch {
      setError("That code is invalid or expired. Request a new one.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>{hasPassword ? "Change password" : "Set a password"}</CardTitle>
        <CardSubtitle>
          {hasPassword
            ? "Update the password for your email sign-in."
            : "Add a password to sign in with your email — not only Google or GitHub."}
        </CardSubtitle>
      </CardHeader>
      <CardContent>
        {step === "idle" ? (
          <div className={s.intro}>
            {done && (
              <Text
                variant="body"
                color="accent-soft-ink"
                className={s.success}
                role="status"
              >
                ✓ Password updated
              </Text>
            )}
            <Text variant="body" color="ink-2">
              For your security, we&apos;ll email a 6-digit code to {email} to
              confirm it&apos;s you before {hasPassword ? "changing" : "setting"}{" "}
              your password.
            </Text>
            {error && (
              <Text variant="body" color="danger" role="alert">
                {error}
              </Text>
            )}
            <div className={s.actions}>
              <Button
                size="sm"
                variant={hasPassword ? "ghost" : "default"}
                disabled={busy}
                onClick={() => void sendCode()}
              >
                {busy ? "Sending…" : "Email me a code"}
              </Button>
            </div>
          </div>
        ) : (
          <Form
            values={{ code, password, confirm }}
            onSubmit={() => void onSubmit()}
            className={s.form}
          >
            {sentCode && (
              <Banner tone="info" role="status">
                Dev code: {sentCode}
              </Banner>
            )}
            <CodeField value={code} onChange={setCode} />
            <Validator
              name="code"
              validate={(v) =>
                String(v ?? "").length === 6 ? null : "Enter the 6-digit code."
              }
            />
            <Field
              label={hasPassword ? "New password" : "Password"}
              htmlFor="sp-new"
              name="password"
              help="At least 10 characters."
            >
              <Input
                id="sp-new"
                type="password"
                autoComplete="new-password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
              />
            </Field>
            <Validator
              name="password"
              rule="required"
              message="Choose a password."
            />
            <Validator name="password" validate={passwordMinError} />
            <Field label="Confirm password" htmlFor="sp-confirm" name="confirm">
              <Input
                id="sp-confirm"
                type="password"
                autoComplete="new-password"
                value={confirm}
                onChange={(e) => setConfirm(e.target.value)}
              />
            </Field>
            <Validator
              name="confirm"
              rule="required"
              message="Re-enter your password."
            />
            <Validator name="confirm" validate={passwordMatchError(password)} />
            {error && (
              <Text variant="body" color="danger" role="alert">
                {error}
              </Text>
            )}
            <div className={s.actions}>
              <Button
                type="submit"
                size="sm"
                variant={hasPassword ? "ghost" : "default"}
                disabled={busy}
              >
                {busy ? "Saving…" : action}
              </Button>
            </div>
          </Form>
        )}
      </CardContent>
    </Card>
  );
}

function Sessions() {
  const navigate = useNavigate();
  const { signOut } = useSession();
  const signOutAll = useSignOutAll();

  async function onSignOut() {
    await signOut();
    navigate("/signin");
  }

  async function onSignOutAll() {
    await signOutAll.mutateAsync();
    await signOut();
    navigate("/signin");
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Sessions</CardTitle>
        <CardSubtitle>Signed in on this browser · just now.</CardSubtitle>
      </CardHeader>
      <CardContent>
        <div className={s.sessionsRow}>
          <Button variant="ghost" size="sm" onClick={() => void onSignOut()}>
            Sign out
          </Button>
          <Button
            variant="destructive"
            size="sm"
            onClick={() => void onSignOutAll()}
            disabled={signOutAll.isPending}
          >
            Sign out of all sessions
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}

export function Security() {
  const { me } = useAccount();
  const identitiesQuery = useIdentities();

  return (
    <div className={layout.stack}>
      <div className={layout.pageHead}>
        <Heading level={1}>Security</Heading>
        <Text variant="body" color="ink-2">
          Sign-in methods and account protection.
        </Text>
      </div>

      <QueryStates result={identitiesQuery}>
        {(identities) => (
          <>
            <ConnectedMethods identities={identities} />
            <PasswordCard
              hasPassword={identities.some((i) => i.provider === "password")}
              email={me.email}
            />
          </>
        )}
      </QueryStates>

      <Sessions />
    </div>
  );
}
