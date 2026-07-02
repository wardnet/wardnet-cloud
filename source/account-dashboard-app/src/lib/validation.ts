/** Pragmatic email check for inline form validation (not RFC-exhaustive). */
export function isValidEmail(value: string): boolean {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value.trim());
}

export const PASSWORD_MIN = 10;

// Validators below match the `<Validator validate>` contract (`@wardnet/ui`):
// return an error message when invalid, or `null` when the value passes. Each
// passes on empty so a sibling `<Validator rule="required">` owns the empty
// case and the field never shows two messages at once.

/** Email-format validator. Passes on empty (let `required` own that). */
export function emailFormatError(value: unknown): string | null {
  const v = String(value ?? "").trim();
  if (v === "") return null;
  return isValidEmail(v) ? null : "Enter a valid email address.";
}

/** Minimum-length password validator. Passes on empty. */
export function passwordMinError(value: unknown): string | null {
  const v = String(value ?? "");
  if (v === "") return null;
  return v.length >= PASSWORD_MIN
    ? null
    : `Use at least ${PASSWORD_MIN} characters.`;
}

/** Factory: a validator asserting the value matches `password`. Passes on empty. */
export function passwordMatchError(
  password: string,
): (value: unknown) => string | null {
  return (value) => {
    const v = String(value ?? "");
    if (v === "") return null;
    return v === password ? null : "Passwords don't match.";
  };
}
