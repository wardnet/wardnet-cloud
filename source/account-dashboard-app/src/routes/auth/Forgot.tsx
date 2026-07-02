import * as React from "react";
import { Link, useNavigate } from "react-router-dom";
import {
  Button,
  Field,
  Form,
  Heading,
  Input,
  Text,
  TextLink,
  Validator,
} from "@wardnet/ui";
import { requestVerificationCode } from "../../api/auth";
import { emailFormatError } from "../../lib/validation";
import { AuthShell } from "./AuthShell";
import { useAuthFlow } from "./AuthFlowContext";
import s from "./auth.module.css";

export function Forgot() {
  const navigate = useNavigate();
  const { set } = useAuthFlow();
  const [email, setEmail] = React.useState("");
  const [error, setError] = React.useState<string | null>(null);
  const [submitting, setSubmitting] = React.useState(false);

  async function onSubmit() {
    setError(null);
    setSubmitting(true);
    try {
      const resp = await requestVerificationCode({
        email,
        purpose: "password_reset",
      });
      set({ email, flow: "reset", sentCode: resp.code ?? null });
      navigate("/confirm");
    } catch {
      setError("Couldn't send the code. Try again.");
      setSubmitting(false);
    }
  }

  return (
    <AuthShell
      footer={
        <Text variant="caption" color="ink-2">
          Remember your password?{" "}
          <TextLink asChild>
            <Link to="/signin">Back to sign in</Link>
          </TextLink>
        </Text>
      }
    >
      <div className={s.head}>
        <Heading level={2}>Reset your password</Heading>
        <Text variant="caption" color="ink-3">
          Enter your account email and we&apos;ll send a 6-character code to reset
          your password.
        </Text>
      </div>

      <Form values={{ email }} onSubmit={onSubmit} className={s.form}>
        <Field
          label="Email"
          htmlFor="fp-email"
          name="email"
          help="Use the email you sign in with."
        >
          <Input
            id="fp-email"
            type="email"
            autoComplete="email"
            placeholder="you@example.com"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
          />
        </Field>
        <Validator name="email" rule="required" message="Email is required." />
        <Validator name="email" validate={emailFormatError} />
        {error && (
          <Text variant="body" color="danger" className={s.danger} role="alert">
            {error}
          </Text>
        )}
        <Button type="submit" className={s.full} disabled={submitting}>
          Send reset code
        </Button>
      </Form>
    </AuthShell>
  );
}
