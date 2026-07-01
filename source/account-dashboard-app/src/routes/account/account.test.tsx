import { beforeEach, describe, expect, it } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { renderApp } from "../../test/utils";
import { server } from "../../mocks/server";
import { resetMockSession, setMockSession } from "../../mocks/handlers";
import { setScenario, type SubScenario } from "../../mocks/scenario";
import { PRICE_BASIC, PRICE_PRO } from "../../mocks/db";

describe("account area (authenticated)", () => {
  beforeEach(() => {
    // Reset first so the mutable mock identities are fresh each test, then log in.
    resetMockSession();
    setMockSession(true);
  });

  describe("Overview — subscription states", () => {
    const cases: [SubScenario, string][] = [
      ["trial", "Trial"],
      ["active", "Active"],
      ["grace", "Grace"],
      ["cancelled", "Cancelled"],
    ];
    it.each(cases)(
      "renders the %s status pill",
      async (subscription, label) => {
        setScenario({ subscription, data: "ready" });
        renderApp("/overview");
        expect(
          await screen.findByRole("heading", { name: "Overview" }),
        ).toBeInTheDocument();
        expect(await screen.findByText(label)).toBeInTheDocument();
        expect(await screen.findByText("WARDNET CLOUD")).toBeInTheDocument();
      },
    );
  });

  describe("Overview — data states", () => {
    it("ready: lists networks and usage tiles", async () => {
      setScenario({ subscription: "trial", data: "ready" });
      renderApp("/overview");
      expect(await screen.findByText("Your networks")).toBeInTheDocument();
      expect(await screen.findByText("home-lab")).toBeInTheDocument();
      expect(screen.getByText("NETWORKS")).toBeInTheDocument();
      expect(screen.getByText("DEVICES")).toBeInTheDocument();
    });

    it("empty: shows the no-networks empty state", async () => {
      setScenario({ subscription: "trial", data: "empty" });
      renderApp("/overview");
      expect(await screen.findByText("No networks yet")).toBeInTheDocument();
    });

    it("error: shows an error card with Retry", async () => {
      setScenario({ subscription: "trial", data: "error" });
      renderApp("/overview");
      expect(
        await screen.findByText("Couldn't load your account."),
      ).toBeInTheDocument();
      expect(screen.getByRole("button", { name: "Retry" })).toBeInTheDocument();
    });

    it("loading: shows neither the ready content nor an error", async () => {
      setScenario({ subscription: "trial", data: "loading" });
      renderApp("/overview");
      // Give the effects a tick; the me query is in-flight (infinite delay).
      await new Promise((r) => setTimeout(r, 20));
      expect(
        screen.queryByRole("heading", { name: "Overview" }),
      ).not.toBeInTheDocument();
      expect(
        screen.queryByText("Couldn't load your account."),
      ).not.toBeInTheDocument();
    });
  });

  describe("Subscription tab", () => {
    it("grace: shows the danger renewal banner", async () => {
      setScenario({ subscription: "grace", data: "ready" });
      renderApp("/subscription");
      expect(
        await screen.findByRole("heading", { name: "Subscription" }),
      ).toBeInTheDocument();
      expect(
        await screen.findByText(/days to renew before it's cancelled/i),
      ).toBeInTheDocument();
    });

    it("active: opens the cancel AlertModal", async () => {
      const user = userEvent.setup();
      setScenario({ subscription: "active", data: "ready" });
      renderApp("/subscription");
      const cancel = await screen.findByRole("button", {
        name: "Cancel subscription",
      });
      await user.click(cancel);
      expect(
        await screen.findByText("Cancel your Pro subscription?"),
      ).toBeInTheDocument();
    });

    it("active: renders the payment method on file", async () => {
      setScenario({ subscription: "active", data: "ready" });
      renderApp("/subscription");
      expect(await screen.findByText(/Visa •••• 4242/)).toBeInTheDocument();
    });

    it("active: shows the catalog with the current plan and up/down actions", async () => {
      setScenario({ subscription: "active", data: "ready" });
      renderApp("/subscription");
      // Current plan (Pro) is marked, and the other levels offer up/down moves.
      expect(await screen.findByText("Current")).toBeInTheDocument();
      expect(
        await screen.findByRole("button", { name: "Upgrade" }),
      ).toBeInTheDocument();
      expect(
        await screen.findByRole("button", { name: "Downgrade" }),
      ).toBeInTheDocument();
    });

    it("active: renders the promo discounted price with a strike-through", async () => {
      setScenario({ subscription: "active", data: "ready" });
      renderApp("/subscription");
      // Pro lists at $8 but the live Holiday promo charges $6.
      expect(await screen.findAllByText("$6.00")).not.toHaveLength(0);
      expect(await screen.findAllByText("$8.00")).not.toHaveLength(0);
    });

    it("trial: a lapsed promo prompts a full-price re-confirm", async () => {
      const user = userEvent.setup();
      // The displayed promo has lapsed: checkout 409s with the real price.
      server.use(
        http.post("/v1/tenants/:id/billing/checkout-session", () =>
          HttpResponse.json(
            {
              error: "promo_unavailable",
              actual_amount_cents: 800,
              currency: "usd",
            },
            { status: 409 },
          ),
        ),
      );
      setScenario({ subscription: "trial", data: "ready" });
      renderApp("/subscription");
      const choose = await screen.findAllByRole("button", { name: "Choose" });
      await user.click(choose[0]);
      expect(
        await screen.findByText("This promotion has ended"),
      ).toBeInTheDocument();
      expect(
        await screen.findByText(/The price is now \$8\.00/),
      ).toBeInTheDocument();
    });

    it("trial: subscribing to a higher tier than the trial confirms the forfeit first", async () => {
      const user = userEvent.setup();
      setScenario({ subscription: "trial", data: "ready" });
      renderApp("/subscription");
      // Plans are Basic / Pro / Team; the trial grants Pro-level entitlement, so only the
      // top tier exceeds it and forfeits the remaining free days (ADR-0012).
      const choose = await screen.findAllByRole("button", { name: "Choose" });
      await user.click(choose[choose.length - 1]);
      expect(
        await screen.findByText("End your free trial?"),
      ).toBeInTheDocument();
      // Backing out keeps the trial.
      await user.click(screen.getByRole("button", { name: "Keep my trial" }));
      await waitFor(() =>
        expect(
          screen.queryByText("End your free trial?"),
        ).not.toBeInTheDocument(),
      );
    });

    it("active: an upgrade flips the current plan immediately (no webhook wait)", async () => {
      const user = userEvent.setup();
      setScenario({ subscription: "active", data: "ready" });
      renderApp("/subscription");
      // Current is Pro (level 2): the only Upgrade offered is the top tier (Team).
      const upgrade = await screen.findByRole("button", { name: "Upgrade" });
      await user.click(upgrade);
      // The current marker moves to Team from the change-plan response, without waiting on
      // the webhook — so no Upgrade action remains.
      await waitFor(() =>
        expect(
          screen.queryByRole("button", { name: "Upgrade" }),
        ).not.toBeInTheDocument(),
      );
    });

    it("active: upgrading during a honored Stripe trial confirms the forfeit first", async () => {
      const user = userEvent.setup();
      // A trial-preserving Home sub reads locally `active`; Billing reports it is still in
      // its Stripe trial via `trialing`.
      server.use(
        http.get("/v1/tenants/:id/billing/subscription", () =>
          HttpResponse.json({
            current_price_id: PRICE_PRO,
            pending_change: null,
            trialing: true,
          }),
        ),
      );
      setScenario({ subscription: "active", data: "ready" });
      renderApp("/subscription");
      const upgrade = await screen.findByRole("button", { name: "Upgrade" });
      await user.click(upgrade);
      expect(
        await screen.findByText("End your free trial?"),
      ).toBeInTheDocument();
    });

    it("active: an upgrade clears the honored-trial flag so a later change doesn't re-confirm", async () => {
      const user = userEvent.setup();
      // Honored trial on Pro (the mock's assumed current plan).
      server.use(
        http.get("/v1/tenants/:id/billing/subscription", () =>
          HttpResponse.json({
            current_price_id: PRICE_PRO,
            pending_change: null,
            trialing: true,
          }),
        ),
      );
      setScenario({ subscription: "active", data: "ready" });
      renderApp("/subscription");
      // Upgrade Pro → Team: confirms the forfeit (trialing), then ends the trial.
      await user.click(await screen.findByRole("button", { name: "Upgrade" }));
      await user.click(
        await screen.findByRole("button", { name: "Subscribe now" }),
      );
      // The optimistic cache now reflects trialing:false — the modal is gone…
      await waitFor(() =>
        expect(
          screen.queryByText("End your free trial?"),
        ).not.toBeInTheDocument(),
      );
      // …and a further change (now on Team) goes through with NO re-confirmation.
      const downgrades = await screen.findAllByRole("button", {
        name: "Downgrade",
      });
      await user.click(downgrades[0]);
      await waitFor(() =>
        expect(
          screen.queryByText("End your free trial?"),
        ).not.toBeInTheDocument(),
      );
    });

    it("active: renders the pending-downgrade banner from the billing subscription", async () => {
      server.use(
        http.get("/v1/tenants/:id/billing/subscription", () =>
          HttpResponse.json({
            current_price_id: PRICE_PRO,
            trialing: false,
            pending_change: {
              price_id: PRICE_BASIC,
              name: "Basic",
              level: 1,
              effective_at: "2026-09-01T00:00:00Z",
            },
          }),
        ),
      );
      setScenario({ subscription: "active", data: "ready" });
      renderApp("/subscription");
      expect(
        await screen.findByText(/Your plan downgrades to Basic on/),
      ).toBeInTheDocument();
    });

    it("active: 'Keep current plan' re-selects the current price to cancel the downgrade", async () => {
      const user = userEvent.setup();
      let changeBody: { price_id?: string } | null = null;
      server.use(
        http.get("/v1/tenants/:id/billing/subscription", () =>
          HttpResponse.json({
            current_price_id: PRICE_PRO,
            trialing: false,
            pending_change: {
              price_id: PRICE_BASIC,
              name: "Basic",
              level: 1,
              effective_at: "2026-09-01T00:00:00Z",
            },
          }),
        ),
        http.post("/v1/tenants/:id/billing/change-plan", async ({ request }) => {
          changeBody = (await request.json()) as { price_id?: string };
          return HttpResponse.json({
            effect: "downgrade_canceled",
            effective_at: null,
            current_price_id: PRICE_PRO,
          });
        }),
      );
      setScenario({ subscription: "active", data: "ready" });
      renderApp("/subscription");
      await user.click(
        await screen.findByRole("button", { name: "Keep current plan" }),
      );
      await waitFor(() => expect(changeBody?.price_id).toBe(PRICE_PRO));
    });

    it("grace: past_due surfaces the open invoice's Pay-now link", async () => {
      server.use(
        http.get("/v1/tenants/:id/billing/invoices", () =>
          HttpResponse.json([
            {
              date: "2026-08-01T00:00:00Z",
              amount_cents: 1490,
              currency: "usd",
              status: "open",
              hosted_url: "https://pay.example.test/inv_open",
            },
          ]),
        ),
      );
      setScenario({ subscription: "grace", data: "ready" });
      renderApp("/subscription");
      const links = await screen.findAllByRole("link", { name: "Pay now" });
      expect(links[0]).toHaveAttribute(
        "href",
        "https://pay.example.test/inv_open",
      );
    });
  });

  describe("Security tab", () => {
    it("shows connected and not-connected sign-in methods", async () => {
      setScenario({ subscription: "active", data: "ready" });
      renderApp("/security");
      expect(
        await screen.findByText("Connected sign-in methods"),
      ).toBeInTheDocument();
      expect(await screen.findByText("pedro@gmail.com")).toBeInTheDocument();
      expect(screen.getByText("Not connected")).toBeInTheDocument();
    });

    it("signs out back to sign-in", async () => {
      const user = userEvent.setup();
      setScenario({ subscription: "active", data: "ready" });
      renderApp("/security");
      const signOut = await screen.findByRole("button", { name: "Sign out" });
      await user.click(signOut);
      expect(
        await screen.findByRole("heading", { name: "Sign in" }),
      ).toBeInTheDocument();
    });

    it("offers to set a password once the password method is disconnected", async () => {
      const user = userEvent.setup();
      setScenario({ subscription: "active", data: "ready" });
      renderApp("/security");
      // Starts with google + password connected → the card is "Change password".
      expect(await screen.findByText("Change password")).toBeInTheDocument();
      // Disconnect the password method (2nd connected: google, password).
      const disconnects = await screen.findAllByRole("button", {
        name: "Disconnect",
      });
      await user.click(disconnects[1]);
      // The card flips to "Set a password" with the email-proof entry point.
      expect(await screen.findByText("Set a password")).toBeInTheDocument();
      expect(
        screen.getByRole("button", { name: "Email me a code" }),
      ).toBeInTheDocument();
    });

    it("sets a password through the email-code flow and flips to change-password", async () => {
      const user = userEvent.setup();
      setScenario({ subscription: "active", data: "ready" });
      renderApp("/security");
      // Disconnect the password method so the card offers to set one.
      const disconnects = await screen.findAllByRole("button", {
        name: "Disconnect",
      });
      await user.click(disconnects[1]);
      await user.click(
        await screen.findByRole("button", { name: "Email me a code" }),
      );
      // Code step: 6 boxes — paste the demo code, then choose a password.
      const boxes = await screen.findAllByRole("textbox");
      expect(boxes).toHaveLength(6);
      await user.click(boxes[0]);
      await user.paste("424242");
      await user.type(screen.getByLabelText("Password"), "averylongpassword");
      await user.type(
        screen.getByLabelText("Confirm password"),
        "averylongpassword",
      );
      await user.click(screen.getByRole("button", { name: "Set password" }));
      // Success: stays signed in, card flips to change-password + confirmation.
      expect(await screen.findByText("✓ Password updated")).toBeInTheDocument();
      expect(await screen.findByText("Change password")).toBeInTheDocument();
    });

    it("explains why the last sign-in method can't be disconnected", async () => {
      const user = userEvent.setup();
      setScenario({ subscription: "active", data: "ready" });
      renderApp("/security");
      const disconnects = await screen.findAllByRole("button", {
        name: "Disconnect",
      });
      // Disconnect google, leaving only the password method.
      await user.click(disconnects[0]);
      await waitFor(() =>
        expect(
          screen.getAllByRole("button", { name: "Disconnect" }),
        ).toHaveLength(1),
      );
      // Attempting to remove the last method explains why instead of doing nothing.
      await user.click(screen.getByRole("button", { name: "Disconnect" }));
      expect(
        await screen.findByText(/only sign-in method/i),
      ).toBeInTheDocument();
    });
  });
});

describe("Demo switcher store", () => {
  it("renders the topbar Demo control in dev", async () => {
    setMockSession(true);
    setScenario({ subscription: "trial", data: "ready" });
    renderApp("/overview");
    const topbar = await screen.findByRole("banner");
    expect(
      within(topbar).getByRole("button", { name: /Demo/ }),
    ).toBeInTheDocument();
  });
});
