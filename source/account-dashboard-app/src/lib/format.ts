/** "Jul 1" — month + day, the prototype's date voice. */
export function formatDate(date: Date | string | null): string {
  if (!date) return "—";
  const d = typeof date === "string" ? new Date(date) : date;
  return d.toLocaleDateString("en-US", { month: "short", day: "numeric" });
}

/** Whole days from now until `date` (clamped at 0). */
export function daysUntil(date: Date | string | null, now = new Date()): number {
  if (!date) return 0;
  const d = typeof date === "string" ? new Date(date) : date;
  const ms = d.getTime() - now.getTime();
  return Math.max(0, Math.ceil(ms / 86_400_000));
}

/** Minor units → "$8.00" (currency symbol best-effort via Intl). */
export function formatMoney(amountCents: number, currency = "usd"): string {
  return new Intl.NumberFormat("en-US", {
    style: "currency",
    currency: currency.toUpperCase(),
  }).format(amountCents / 100);
}

/** Card expiry "08/27" from month + 4-digit year. */
export function formatExpiry(month: number, year: number): string {
  const mm = String(month).padStart(2, "0");
  const yy = String(year).slice(-2);
  return `${mm} / ${yy}`;
}

/** Title-case a card brand ("visa" → "Visa"). */
export function titleCase(value: string): string {
  return value.charAt(0).toUpperCase() + value.slice(1);
}
