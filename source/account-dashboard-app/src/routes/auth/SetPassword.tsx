import * as React from "react";
import { Link, Navigate, useNavigate } from "react-router-dom";
import {
  Button,
  Field,
  Form,
  Heading,
  Input,
  Pill,
  Text,
  TextLink,
  Validator,
} from "@wardnet/ui";
import { passwordReset, passwordSignup } from "../../api/auth";
import { useSession } from "../../auth/AuthProvider";
import { passwordMatchError, passwordMinError } from "../../lib/validation";
import { AuthShell } from "./AuthShell";
import { useAuthFlow } from "./AuthFlowContext";
import s from "./auth.module.css";

export function SetPassword() {
  const navigate = useNavigate();
  const { refresh } = useSession();
  const { email, code, flow } = useAuthFlow();

  const [displayName, setDisplayName] = React.useState("");
  const [password, setPassword] = React.useState("");
  const [confirm, setConfirm] = React.useState("");
  const [error, setError] = React.useState<string | null>(null);
  const [submitting, setSubmitting] = React.useState(false);

  // Guard against a deep-link without a verified code.
  if (!email || !code) {
    return <Navigate to="/signin" replace />;
  }

  const isSignup = flow === "signup";

  async function onSubmit() {
    setError(null);
    setSubmitting(true);
    try {
      if (isSignup) {
        await passwordSignup({ email, code, password });
        await refresh();
        navigate("/overview");
      } else {
        await passwordReset({ code, password });
        navigate("/signin", {
          state: { note: "Password updated. Sign in with your new password." },
        });
      }
    } catch {
      setError("That code is no longer valid. Start again.");
      setSubmitting(false);
    }
  }

  return (
    <AuthShell
      footer={
        <Text variant="caption" color="ink-2">
          Changed your mind?{" "}
          <TextLink asChild>
            <Link to="/signin">Back to sign in</Link>
          </TextLink>
        </Text>
      }
    >
      <div className={s.pillRow}>
        <Pill variant="ok">{isSignup ? "Email verified" : "Identity verified"}</Pill>
      </div>
      <div className={s.head}>
        <Heading level={2}>
          {isSignup ? "Finish setting up" : "Set a new password"}
        </Heading>
        <Text variant="caption" color="ink-3">
          {isSignup
            ? "Choose a display name and password to secure your account."
            : `Choose a new password for ${email}.`}
        </Text>
      </div>

      <Form
        values={{ displayName, password, confirm }}
        onSubmit={onSubmit}
        className={s.form}
      >
        {isSignup && (
          <Field label="Display name" htmlFor="sp-name" name="displayName">
            <Input
              id="sp-name"
              autoComplete="nickname"
              placeholder="Pedro"
              value={displayName}
              onChange={(e) => setDisplayName(e.target.value)}
            />
          </Field>
        )}
        <Field
          label={isSignup ? "Password" : "New password"}
          htmlFor="sp-password"
          name="password"
          help="At least 10 characters."
        >
          <Input
            id="sp-password"
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
          <Text variant="body" color="danger" className={s.danger} role="alert">
            {error}
          </Text>
        )}
        <Button type="submit" className={s.full} disabled={submitting}>
          {isSignup ? "Create account & continue" : "Update password & sign in"}
        </Button>
      </Form>
    </AuthShell>
  );
}
