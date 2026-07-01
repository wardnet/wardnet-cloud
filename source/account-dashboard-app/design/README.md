# Handoff: Wardnet — My Account

A web SPA where **Wardnet Cloud** customers sign in, manage their profile, and
manage their subscription. Wardnet is a self-hosted network-privacy gateway (runs
on a Raspberry Pi); a Cloud account unlocks premium features — **dynamic DNS** and
**secure remote tunneling** — gated by a subscription.

## What's in this folder
- `Wardnet - My Account.dc.html` — the working design reference (the full app).
- `README.md` — this spec.

## How to read the design file
It's a **high-fidelity HTML prototype**, not production code to copy line-for-line.
The whole app is rendered from one JavaScript class via `React.createElement`
against a pre-bundled `@wardnet/ui`. **Recreate it in the target codebase** using
that project's framework, routing, and data layer. If the team consumes
`@wardnet/ui` from npm, compose the real components named below rather than
re-implementing them. To preview the reference: open it in a browser.

## Fidelity: high
Colors, type, spacing, components, copy, and interactions are all settled.
Everything maps to a `@wardnet/ui` component or a design token — don't invent new
colors or type scales.

---

## Design system: @wardnet/ui (v0.1.0)
Dense, technical admin UI. Warm Paper surfaces, deep Ink text, single Emerald
accent. **One emerald primary `Button` per view; everything else ghost/ink.**
Typography always via `<Text variant=…>` / `<Heading level=…>` — never raw
font-size. Layout glue uses CSS-variable tokens (`var(--bg)`, `var(--bg-card)`,
`var(--ink)`, `var(--ink-3)`, `var(--accent)`, `var(--line)`, `var(--radius-lg)`,
`var(--shadow-card)`, `--danger`/`--warn`/`--info` + their `-soft` variants).

**Theming:** light is default; set `data-theme="dark"` on an ancestor (the
prototype sets it on `<html>` so portalled modals/menus inherit). A sun/moon ghost
icon-button toggles it.

**Components used:** `Card` (+ `CardHeader/CardTitle/CardSubtitle/CardAction/
CardContent`), `Button`, `Text`, `Heading`, `Field`, `Input`, `Banner`, `Pill`,
`StatTile`, `Modal` (+ `ModalContent/Header/Title/Body/Description/Footer/Close`),
`AlertModal` (+ `Trigger/Content/Header/Title/Body/Description/Footer/Cancel/
Action`), `DropdownMenu` (+ `Trigger/Content/Item/Separator`), `Logo`.

---

## Data model (drives the UI)
A **subscription** has a `status`: `Trial → Grace → Cancelled`, or `Active`.
It grants **entitlements**: `maxNetworks`, `maxDevices`. Surface usage-vs-limit
everywhere; show warn tone near a limit and pause premium actions when not active.

Sample data: user **Pedro** (`pedro@example.com`), plan **Pro $8/mo**,
networks **2/3** (`home-lab` Online, `parents-house` Degraded), devices **24/25**
(near limit → warn), card **Visa •••• 4242**, renews **Jul 1**.

---

## AUTH (unauthenticated)
Centered 392px column on a Paper canvas: centered **Logo** above a `Card`
(padding 26). Theme toggle pinned top-right. Two OIDC buttons are **ghost**,
full-width, with the provider glyph (full-color Google G, monochrome GitHub) +
label, separated from the email form by an **"or" divider** (centered micro text
flanked by `var(--line)` rules).

1. **Sign in** — Google/GitHub, "or", Email + Password `Field`s, right-aligned
   "Forgot password?", emerald "Sign in". Footer "Create an account". An info
   `Banner` appears here only after a completed password reset.
2. **Create an account** — Google/GitHub, "or", Email `Field` (validated inline),
   emerald "Send confirmation code" → confirm screen with `flow='signup'`.
3. **Confirm email / code** — heading "Confirm your email" (signup) or "Enter the
   reset code" (reset). "We sent a 6-digit code to {email}." A **segmented 6-box
   code input**: digits only, auto-advance, backspace-to-previous, arrow nav,
   **paste fills all six**, autofocus first. Emerald "Verify" (demo code `424242`;
   wrong/empty → inline danger error). "Resend code" with cooldown
   ("Resend in 0:42") and "Change email" (routes back to register or forgot per
   flow).
4. **Set password** — after verify. Signup: "Email verified" pill + display-name +
   password + confirm → creates account, lands in Overview (Trial). Reset:
   "Identity verified" pill, **no display-name**, new password + confirm →
   "Update password & sign in", returns to Sign in with the success banner.
   Password rules: min 10 chars, confirm must match (inline `Field error`).
5. **Forgot / reset password** (from "Forgot password?") — "Reset your password",
   Email `Field` (validated), emerald "Send reset code" → confirm screen with
   `flow='reset'`. Footer "Back to sign in".

State that drives auth: `authScreen` (signin|register|forgot|confirm|setpw),
`flow` (signup|reset), `pendingEmail`, `code[6]`, `codeError`, `emailError`,
`pw`/`pw2`/`pwErrors`, `resendIn`, `signinNote`.

---

## ACCOUNT (authenticated)
App shell: sticky top bar (max-width 940, centered) — **Logo**, tab nav
(Overview · Subscription · Security) with an emerald underline on the active tab,
spacer, a **Demo** dropdown (reviewer control — switches subscription state and
data state; remove in production), theme toggle, and an **account menu**
(avatar + name → email, tab links, destructive Sign out).

Data states each tab handles: **loading** (shimmer skeleton cards), **error**
(centered card + Retry), **empty** (where relevant), **ready**.

### Overview
- **Status card** — left emerald (or warn/muted) accent stripe, "WARDNET CLOUD"
  label + status `Pill`, a state-specific headline + sentence + one CTA:
  - Trial → "Your Pro trial ends in 5 days" · **Add payment method**
  - Active → "Pro · renews on Jul 1" · ghost **Manage subscription**
  - Grace → "Your subscription expired on Jun 20" (warn) · **Renew now**
  - Cancelled → "Cancelled on Jun 24" (muted) · **Reactivate**
- **Two `StatTile`s** with usage bars: Networks 2/3, Devices 24/25 (Devices shows
  a warn "Near limit" pill + warn bar when ≤1 slot left).
- **Networks list** — name (mono), region, device count, status `Pill`. Empty
  state explains networks are created automatically on gateway install (no "Add
  network" button — pairing a device creates them). When grace/cancelled, show a
  "Premium paused" pill instead of actions.

### Subscription
- Top row: **Plan card** (name, `$8`/`mo` metric, status `Pill`) and
  **Entitlements card** (Networks + Devices rows, each a usage meter; warn tone on
  the near-limit row). Both cards stretch to **equal height** (`align-items:
  stretch` on the grid).
- **Grace** shows a danger `Banner` at top: "Your subscription expired on Jun 20.
  You have 4 days to renew before it's cancelled and premium features stop." +
  emerald **Renew now**.
- **Lifecycle card** — state-specific: Trial (countdown + "what happens at trial
  end" + Add payment / Upgrade), Active (renews + card, with Change plan / Update
  payment / **Cancel subscription**), Grace (Renew now / Update payment),
  Cancelled (Reactivate).
- **Payment method card** — Visa •••• 4242, Expires 08/27, ghost **Update**.
- **Billing history** — table (Date, Amount mono, status `Pill`, download icon).
- **Update payment `Modal`** — Stripe represented as discrete `@wardnet/ui`
  `Input` fields: **Card number**, an **Expiry / CVC** row, **Name on card**
  (each its own field so the focus ring isn't clipped). Saving from Trial → Active.
- **Cancel subscription** opens an **`AlertModal`** explaining the consequence
  (premium ends at period end; entitlements drop to free limits) → destructive
  "Cancel at period end" sets status Cancelled.

### Security
- **Connected sign-in methods** — Google (connected, email shown), GitHub (not
  connected → Connect), Email & password (connected). Each row has a connect /
  disconnect action; at least one method must remain.
- **Change password** — current + new password `Field`s, confirmation note.
- **Sessions** — "Sign out" and destructive "Sign out of all sessions".

---

## Implementation notes
- Subscription state is the spine — derive every status pill, CTA, banner, and
  blocked/near-limit action from it. Centralize `status` + entitlement usage and
  compute presentation from there.
- OIDC buttons stay visually secondary to the brand's own primary action.
- Hit targets ≥ 44px; hairline dividers are `var(--line)`; soft `var(--shadow-card)`.
- The **Demo** dropdown is a reviewer affordance only — drop it in production and
  drive state from the real subscription/auth backend.
