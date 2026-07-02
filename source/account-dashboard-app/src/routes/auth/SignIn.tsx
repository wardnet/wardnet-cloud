import * as React from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import {
  Banner,
  Button,
  Field,
  Form,
  Heading,
  Input,
  Text,
  TextLink,
  Validator,
} from "@wardnet/ui";
import { passwordLogin } from "../../api/auth";
import { emailFormatError } from "../../lib/validation";
import { useSession } from "../../auth/AuthProvider";
import { AuthShell } from "./AuthShell";
import { OAuthOptions } from "./OAuthOptions";
import s from "./auth.module.css";

export function SignIn() {
  const navigate = useNavigate();
  const location = useLocation();
  const { refresh } = useSession();
  const note = (location.state as { note?: string } | null)?.note;

  const [email, setEmail] = React.useState("");
  const [password, setPassword] = React.useState("");
  const [error, setError] = React.useState<string | null>(null);
  const [submitting, setSubmitting] = React.useState(false);

  async function onSubmit() {
    setError(null);
    setSubmitting(true);
    try {
      await passwordLogin({ email, password });
      await refresh();
      navigate("/overview");
    } catch {
      setError("Incorrect email or password.");
      setSubmitting(false);
    }
  }

  return (
    <AuthShell
      footer={
        <Text variant="caption" color="ink-2">
          Don&apos;t have an account?{" "}
          <TextLink asChild>
            <Link to="/register">Create an account</Link>
          </TextLink>
        </Text>
      }
    >
      <div className={s.head}>
        <Heading level={2}>Sign in</Heading>
        <Text variant="caption" color="ink-3">
          Access your Wardnet Cloud account.
        </Text>
      </div>

      {note && (
        <Banner tone="info" role="status">
          {note}
        </Banner>
      )}

      <OAuthOptions />

      <Form values={{ email, password }} onSubmit={onSubmit} className={s.form}>
        <Field label="Email" htmlFor="si-email" name="email">
          <Input
            id="si-email"
            type="email"
            autoComplete="email"
            placeholder="you@example.com"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
          />
        </Field>
        <Validator name="email" rule="required" message="Email is required." />
        <Validator name="email" validate={emailFormatError} />
        <Field label="Password" htmlFor="si-password" name="password">
          <Input
            id="si-password"
            type="password"
            autoComplete="current-password"
            placeholder="••••••••"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
        </Field>
        <Validator
          name="password"
          rule="required"
          message="Password is required."
        />
        <div className={s.forgotRow}>
          <TextLink asChild>
            <Link to="/forgot">Forgot password?</Link>
          </TextLink>
        </div>
        {error && (
          <Text variant="body" color="danger" className={s.danger} role="alert">
            {error}
          </Text>
        )}
        <Button type="submit" className={s.full} disabled={submitting}>
          Sign in
        </Button>
      </Form>
    </AuthShell>
  );
}
