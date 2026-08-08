import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import App from "./App";
import { api } from "./api/client";

vi.mock("./api/client", async () => {
  const actual = await vi.importActual<typeof import("./api/client")>("./api/client");
  return {
    ...actual,
    api: {
      listStagedDiffs: vi.fn(),
      listGrants: vi.fn(),
      listGrantRequests: vi.fn(),
      listTokens: vi.fn(),
      createToken: vi.fn(),
      revokeToken: vi.fn(),
    },
  };
});

const created = {
  id: "token-2",
  label: "alex-phone",
  active: true,
  created_at: "2026-08-07T00:00:00Z",
  token: "plaintext-bearer-token",
  totp_enroll_uri: "otpauth://totp/Chuvar:alex-phone?secret=JBSWY3DPEHPK3PXP&issuer=Chuvar",
};

// Switching tabs unmounts the page outright, so a pending reveal — a bearer
// token and TOTP setup key that exist nowhere else, the server having kept only
// a hash — would be destroyed silently. On a first device that also latches the
// enrollment gate permanently, leaving no credential able to mint a replacement.
// These tests cover the guard that stands between a stray click and DB surgery.
describe("App tab navigation with a pending token reveal", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(api.listStagedDiffs).mockResolvedValue([]);
    vi.mocked(api.listGrants).mockResolvedValue([]);
    vi.mocked(api.listGrantRequests).mockResolvedValue([]);
    vi.mocked(api.listTokens).mockResolvedValue([]);
    vi.mocked(api.createToken).mockResolvedValue(created);
    vi.spyOn(window, "prompt").mockReturnValue("");
    vi.spyOn(window, "confirm").mockReturnValue(true);
  });

  async function revealATokenOnTheTokensTab() {
    render(<App />);
    await userEvent.click(screen.getByRole("button", { name: "Tokens" }));
    await screen.findByText("No reviewer tokens yet.");
    await userEvent.type(screen.getByPlaceholderText("alex-laptop"), "alex-phone");
    await userEvent.click(screen.getByRole("button", { name: "Create token" }));
    await screen.findByDisplayValue("plaintext-bearer-token");
  }

  it("keeps the reveal on screen when the operator declines the leave confirmation", async () => {
    await revealATokenOnTheTokensTab();

    vi.mocked(window.confirm).mockReturnValue(false);
    await userEvent.click(screen.getByRole("button", { name: "Grants" }));

    expect(screen.getByDisplayValue("plaintext-bearer-token")).toBeInTheDocument();
  });

  it("leaves the tab, discarding the reveal, once the operator confirms", async () => {
    await revealATokenOnTheTokensTab();

    await userEvent.click(screen.getByRole("button", { name: "Grants" }));

    expect(screen.queryByDisplayValue("plaintext-bearer-token")).not.toBeInTheDocument();
  });

  it("does not prompt when switching tabs with no reveal pending", async () => {
    render(<App />);
    await userEvent.click(screen.getByRole("button", { name: "Tokens" }));
    await screen.findByText("No reviewer tokens yet.");

    await userEvent.click(screen.getByRole("button", { name: "Grants" }));

    expect(window.confirm).not.toHaveBeenCalled();
  });
});
