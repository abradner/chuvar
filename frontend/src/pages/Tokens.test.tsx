import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { TokensPage } from "./Tokens";
import { api } from "../api/client";
import type { CreatedReviewerToken, ReviewerToken } from "../api/client";

vi.mock("../api/client", async () => {
  const actual = await vi.importActual<typeof import("../api/client")>("../api/client");
  return {
    ...actual,
    api: {
      listTokens: vi.fn(),
      createToken: vi.fn(),
      revokeToken: vi.fn(),
    },
  };
});

const sampleToken: ReviewerToken = {
  id: "token-1",
  label: "alex-laptop",
  active: true,
  created_at: "2026-07-23T00:00:00Z",
};

const sampleCreated: CreatedReviewerToken = {
  id: "token-2",
  label: "alex-phone",
  active: true,
  created_at: "2026-08-07T00:00:00Z",
  token: "plaintext-bearer-token",
  totp_enroll_uri: "otpauth://totp/Chuvar:alex-phone?secret=JBSWY3DPEHPK3PXP&issuer=Chuvar",
};

describe("TokensPage", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    // createToken's TOTP prompt is optional (unlike Grants.tsx's TOTP
    // prompts) — default to "no code entered", the bootstrap-enrollment path.
    vi.spyOn(window, "prompt").mockReturnValue("");
  });

  it("renders existing tokens", async () => {
    vi.mocked(api.listTokens).mockResolvedValue([sampleToken]);

    render(<TokensPage />);

    expect(await screen.findByText("alex-laptop")).toBeInTheDocument();
    expect(screen.getByText("active")).toBeInTheDocument();
  });

  it("shows an empty state when there are no tokens yet", async () => {
    vi.mocked(api.listTokens).mockResolvedValue([]);

    render(<TokensPage />);

    expect(await screen.findByText("No reviewer tokens yet.")).toBeInTheDocument();
  });

  it("reveals the plaintext token and TOTP secret exactly once after creating", async () => {
    vi.mocked(api.listTokens).mockResolvedValue([]);
    vi.mocked(api.createToken).mockResolvedValue(sampleCreated);

    render(<TokensPage />);
    await screen.findByText("No reviewer tokens yet.");

    await userEvent.type(screen.getByPlaceholderText("alex-laptop"), "alex-phone");
    await userEvent.click(screen.getByRole("button", { name: "Create token" }));

    expect(await screen.findByDisplayValue("plaintext-bearer-token")).toBeInTheDocument();
    expect(screen.getByDisplayValue("JBSWY3DPEHPK3PXP")).toBeInTheDocument();
    // createToken is called with the bootstrap path's undefined totpCode, not
    // an empty string — window.prompt's mocked "" return must be normalized,
    // since the backend distinguishes "no code sent" from "empty code sent".
    expect(api.createToken).toHaveBeenCalledWith("alex-phone", undefined);
  });

  it("falls back to the raw URI when the enrollment URI cannot be parsed", async () => {
    // A parse failure during render would blank the page rather than degrade,
    // and the secret is unrecoverable after this one render — so the fallback
    // shows something enrollable instead of throwing. See enrollmentSecret.
    vi.mocked(api.listTokens).mockResolvedValue([]);
    vi.mocked(api.createToken).mockResolvedValue({ ...sampleCreated, totp_enroll_uri: "not a valid uri" });

    render(<TokensPage />);
    await screen.findByText("No reviewer tokens yet.");
    await userEvent.type(screen.getByPlaceholderText("alex-laptop"), "alex-phone");
    await userEvent.click(screen.getByRole("button", { name: "Create token" }));

    expect(await screen.findByDisplayValue("not a valid uri")).toBeInTheDocument();
  });

  it("falls back to the raw URI when the enrollment URI carries an empty secret", async () => {
    // searchParams.get returns "" (not null) for a valueless `?secret=`, so a
    // `??` fallback would leave the setup key field blank — the operator would
    // have nothing to enrol from and no way to recover it. Found in review.
    vi.mocked(api.listTokens).mockResolvedValue([]);
    vi.mocked(api.createToken).mockResolvedValue({
      ...sampleCreated,
      totp_enroll_uri: "otpauth://totp/Chuvar:alex-phone?secret=&issuer=Chuvar",
    });

    render(<TokensPage />);
    await screen.findByText("No reviewer tokens yet.");
    await userEvent.type(screen.getByPlaceholderText("alex-laptop"), "alex-phone");
    await userEvent.click(screen.getByRole("button", { name: "Create token" }));

    expect(
      await screen.findByDisplayValue("otpauth://totp/Chuvar:alex-phone?secret=&issuer=Chuvar"),
    ).toBeInTheDocument();
  });

  it("dismisses the revealed token without re-showing it after dismiss", async () => {
    vi.mocked(api.listTokens).mockResolvedValue([]);
    vi.mocked(api.createToken).mockResolvedValue(sampleCreated);

    render(<TokensPage />);
    await screen.findByText("No reviewer tokens yet.");
    await userEvent.type(screen.getByPlaceholderText("alex-laptop"), "alex-phone");
    await userEvent.click(screen.getByRole("button", { name: "Create token" }));
    await screen.findByDisplayValue("plaintext-bearer-token");

    await userEvent.click(screen.getByRole("button", { name: "Dismiss" }));

    expect(screen.queryByDisplayValue("plaintext-bearer-token")).not.toBeInTheDocument();
  });

  it("reflects the revoked state after revoking, not just calling the API", async () => {
    // The reload after revoke is the part worth asserting: mocking listTokens
    // to return the same active token forever would let this pass even if the
    // list were never refreshed at all.
    vi.mocked(api.listTokens)
      .mockResolvedValueOnce([sampleToken])
      .mockResolvedValue([{ ...sampleToken, active: false, revoked_at: "2026-08-07T12:00:00Z" }]);
    vi.mocked(api.revokeToken).mockResolvedValue(undefined);

    render(<TokensPage />);
    await screen.findByText("active");

    await userEvent.click(screen.getByRole("button", { name: "Revoke" }));

    expect(await screen.findByText("revoked")).toBeInTheDocument();
    expect(api.revokeToken).toHaveBeenCalledWith("token-1");
    expect(screen.queryByRole("button", { name: "Revoke" })).not.toBeInTheDocument();
  });

  it("aborts creation when the TOTP prompt is cancelled", async () => {
    // Cancel (null) and submitted-blank ("") are different answers: blank is a
    // legitimate bootstrap enrollment, cancel means don't create at all.
    vi.mocked(api.listTokens).mockResolvedValue([]);
    vi.spyOn(window, "prompt").mockReturnValue(null);

    render(<TokensPage />);
    await screen.findByText("No reviewer tokens yet.");
    await userEvent.type(screen.getByPlaceholderText("alex-laptop"), "alex-phone");
    await userEvent.click(screen.getByRole("button", { name: "Create token" }));

    expect(api.createToken).not.toHaveBeenCalled();
  });

  it("refuses to create another token until the revealed one is dismissed", async () => {
    // The revealed secret is unrecoverable, so a second create must not be
    // able to overwrite it before the operator has copied it.
    vi.mocked(api.listTokens).mockResolvedValue([]);
    vi.mocked(api.createToken).mockResolvedValue(sampleCreated);

    render(<TokensPage />);
    await screen.findByText("No reviewer tokens yet.");
    await userEvent.type(screen.getByPlaceholderText("alex-laptop"), "alex-phone");
    await userEvent.click(screen.getByRole("button", { name: "Create token" }));
    await screen.findByDisplayValue("plaintext-bearer-token");

    expect(screen.getByRole("button", { name: "Create token" })).toBeDisabled();
    expect(api.createToken).toHaveBeenCalledTimes(1);

    // Still reachable via Enter on the form even with the button disabled.
    await userEvent.type(screen.getByPlaceholderText("alex-laptop"), "second-device{Enter}");
    expect(api.createToken).toHaveBeenCalledTimes(1);
    expect(screen.getByDisplayValue("plaintext-bearer-token")).toBeInTheDocument();
  });
});
