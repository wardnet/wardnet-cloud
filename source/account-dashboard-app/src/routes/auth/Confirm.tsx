import * as React from "react";
import { Link, Navigate, useNavigate } from "react-router-dom";
import {
  Banner,
  Button,
  CodeInput,
  Form,
  Heading,
  Text,
  TextLink,
  useFormContext,
  Validator,
} from "@wardnet/ui";
import { requestVerificationCode } from "../../api/auth";
import { MSW_ENABLED } from "../../config/env";
import { DEMO_CODE } from "../../mocks/db";
import { AuthShell } from "./AuthShell";
import { useAuthFlow } from "./AuthFlowContext";
import s from "./auth.module.css";

const RESEND_SECONDS = 45;

/** Renders the 6-box code input and surfaces its `<Validator name="code">`
 *  error from the parent `<Form>` context (CodeInput is not a `<Field>`). */
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
        autoFocus
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

export function Confirm() {
  const navigate = useNavigate();
  const { email, flow, set, sentCode } = useAuthFlow();
  const [code, setCode] = React.useState("");
  const [resendIn, setResendIn] = React.useState(RESEND_SECONDS);

  // Which code to hint, if any. Under MSW it's the fixed demo code; against a real
  // backend that isn't emailing (no Resend key), the backend returns the code and
  // we surface it; when email is actually delivered there's no code to show.
  const hintCode = MSW_ENABLED ? DEMO_CODE : sentCode;

  React.useEffect(() => {
    if (resendIn <= 0) return;
    const t = setTimeout(() => setResendIn((n) => n - 1), 1000);
    return () => clearTimeout(t);
  }, [resendIn]);

  // Guard against a deep-link without a pending email.
  if (!email) {
    return <Navigate to={flow === "reset" ? "/forgot" : "/register"} replace />;
  }

  function onVerify() {
    set({ code });
    navigate("/set-password");
  }

  async function onResend() {
    const resp = await requestVerificationCode({
      email,
      purpose: flow === "reset" ? "password_reset" : "signup",
    });
    set({ sentCode: resp.code ?? null });
    setResendIn(RESEND_SECONDS);
  }

  const mmss = `0:${String(resendIn).padStart(2, "0")}`;

  return (
    <AuthShell
      footer={
        <Text variant="caption" color="ink-2">
          <TextLink asChild>
            <Link to={flow === "reset" ? "/forgot" : "/register"}>
              Change email
            </Link>
          </TextLink>
        </Text>
      }
    >
      <div className={s.head}>
        <Heading level={2}>
          {flow === "reset" ? "Enter the reset code" : "Confirm your email"}
        </Heading>
        <Text variant="caption" color="ink-3">
          We sent a 6-character code to {email}.
        </Text>
      </div>

      {hintCode && (
        <Banner tone="info" role="status">
          {MSW_ENABLED ? "Demo" : "Dev"} code: {hintCode}
        </Banner>
      )}

      <Form values={{ code }} onSubmit={onVerify} className={s.form}>
        <CodeField value={code} onChange={setCode} />
        <Validator
          name="code"
          validate={(v) =>
            String(v ?? "").length === 6 ? null : "Enter the 6-character code."
          }
        />
        <Button type="submit" className={s.full}>
          Verify
        </Button>
        <div className={s.resendRow}>
          {resendIn > 0 ? (
            <Text variant="caption" color="ink-3">
              Resend in {mmss}
            </Text>
          ) : (
            <TextLink
              onClick={(e) => {
                e.preventDefault();
                void onResend();
              }}
            >
              Resend code
            </TextLink>
          )}
        </div>
      </Form>
    </AuthShell>
  );
}
