import { describe, expect, it } from "vitest";
import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { renderApp } from "../../test/utils";

describe("authentication flow", () => {
  it("signs in with email + password and lands on Overview", async () => {
    const user = userEvent.setup();
    renderApp("/signin");

    expect(
      await screen.findByRole("heading", { name: "Sign in" }),
    ).toBeInTheDocument();

    await user.type(screen.getByLabelText("Email"), "pedro@example.com");
    await user.type(screen.getByLabelText("Password"), "supersecret");
    await user.click(screen.getByRole("button", { name: "Sign in" }));

    expect(
      await screen.findByRole("heading", { name: "Overview" }),
    ).toBeInTheDocument();
  });

  it("completes the signup → confirm → set-password journey", async () => {
    const user = userEvent.setup();
    renderApp("/register");

    await user.type(
      await screen.findByLabelText("Email"),
      "new@example.com",
    );
    await user.click(
      screen.getByRole("button", { name: "Send confirmation code" }),
    );

    // Confirm screen: paste-fills-all into the 6-box code input.
    expect(
      await screen.findByRole("heading", { name: "Confirm your email" }),
    ).toBeInTheDocument();
    const boxes = screen.getAllByRole("textbox");
    expect(boxes).toHaveLength(6);
    await user.click(boxes[0]);
    await user.paste("424242");
    await user.click(screen.getByRole("button", { name: "Verify" }));

    // Set-password screen.
    expect(
      await screen.findByRole("heading", { name: "Finish setting up" }),
    ).toBeInTheDocument();
    await user.type(screen.getByLabelText("Password"), "averylongpassword");
    await user.type(
      screen.getByLabelText("Confirm password"),
      "averylongpassword",
    );
    await user.click(
      screen.getByRole("button", { name: "Create account & continue" }),
    );

    expect(
      await screen.findByRole("heading", { name: "Overview" }),
    ).toBeInTheDocument();
  });

  it("rejects an incomplete code with an inline error", async () => {
    const user = userEvent.setup();
    renderApp("/register");
    await user.type(await screen.findByLabelText("Email"), "new@example.com");
    await user.click(
      screen.getByRole("button", { name: "Send confirmation code" }),
    );
    await screen.findByRole("heading", { name: "Confirm your email" });

    const boxes = screen.getAllByRole("textbox");
    await user.click(boxes[0]);
    await user.paste("12");
    await user.click(screen.getByRole("button", { name: "Verify" }));

    expect(
      await screen.findByText("Enter the 6-character code."),
    ).toBeInTheDocument();
  });

  it("redirects unauthenticated access to a protected route to sign-in", async () => {
    renderApp("/overview");
    expect(
      await screen.findByRole("heading", { name: "Sign in" }),
    ).toBeInTheDocument();
  });
});
