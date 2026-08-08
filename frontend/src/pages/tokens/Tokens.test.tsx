import { act, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { TokensPage } from "./Tokens";
import { api, ApiError } from "../../api/client";
import type { CreatedReviewerToken, ReviewerToken } from "../../api/client";

vi.mock("../../api/client", async () => {
  const actual = await vi.importActual<typeof import("../../api/client")>("../../api/client");
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

// Walks the create form from an empty list to a rendered reveal panel.
async function createAndReveal() {
  await screen.findByText("No reviewer tokens yet.");
  await userEvent.type(screen.getByPlaceholderText("alex-laptop"), "alex-phone");
  await userEvent.click(screen.getByRole("button", { name: "Create token" }));
  await screen.findByDisplayValue("plaintext-bearer-token");
}

describe("TokensPage", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    // createToken's TOTP prompt is optional (unlike Grants.tsx's TOTP
    // prompts) — default to "no code entered", the fresh-install path.
    vi.spyOn(window, "prompt").mockReturnValue("");
    // Dismiss and Revoke both confirm; default to "operator said yes" so each
    // test only has to override the case it is actually about.
    vi.spyOn(window, "confirm").mockReturnValue(true);
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

  it("does not claim the list is empty while the initial load is still pending", async () => {
    // tokens starts as [] regardless of whether the first fetch has returned,
    // so without a loading flag this rendered identically to a confirmed-empty
    // inventory. Found in review (Copilot).
    let resolveList!: (tokens: ReviewerToken[]) => void;
    vi.mocked(api.listTokens).mockReturnValue(new Promise((resolve) => (resolveList = resolve)));

    render(<TokensPage />);

    expect(screen.queryByText("No reviewer tokens yet.")).not.toBeInTheDocument();

    await act(async () => resolveList([]));
    expect(await screen.findByText("No reviewer tokens yet.")).toBeInTheDocument();
  });

  it("does not claim the list is empty when the initial load fails", async () => {
    vi.mocked(api.listTokens).mockRejectedValue(new ApiError(500, "boom"));

    render(<TokensPage />);

    expect(await screen.findByText("boom")).toBeInTheDocument();
    expect(screen.queryByText("No reviewer tokens yet.")).not.toBeInTheDocument();
  });

  it("reveals the plaintext token and TOTP secret exactly once after creating", async () => {
    vi.mocked(api.listTokens).mockResolvedValue([]);
    vi.mocked(api.createToken).mockResolvedValue(sampleCreated);

    render(<TokensPage />);
    await createAndReveal();

    expect(screen.getByDisplayValue("JBSWY3DPEHPK3PXP")).toBeInTheDocument();
    // Shape check only: a blank prompt sends no code. (The backend treats an
    // absent and an empty X-Chuvar-TOTP-Code header identically — verifyTOTPCode
    // trims then compares to "" — so this is not a security boundary, and
    // client.ts omits the header for "" anyway.)
    expect(api.createToken).toHaveBeenCalledWith("alex-phone", undefined);
  });

  it("sends a real TOTP code trimmed of paste whitespace", async () => {
    // Only the blank and cancel branches were previously exercised; a
    // regression that dropped or failed to trim a real code would make every
    // post-bootstrap enrollment fail while those tests stayed green. Found in
    // review (Copilot).
    vi.mocked(api.listTokens).mockResolvedValue([]);
    vi.mocked(api.createToken).mockResolvedValue(sampleCreated);
    vi.spyOn(window, "prompt").mockReturnValue("  123456  ");

    render(<TokensPage />);
    await createAndReveal();

    expect(api.createToken).toHaveBeenCalledWith("alex-phone", "123456");
  });

  it("falls back to the raw URI when the enrollment URI cannot be parsed", async () => {
    // A parse failure during render would blank the page rather than degrade,
    // and the secret is unrecoverable after this one render. See enrollmentSecret.
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

  it("aborts creation when the TOTP prompt is cancelled", async () => {
    // Cancel (null) and submitted-blank ("") are different answers: blank is a
    // legitimate fresh-install enrollment, cancel means don't create at all.
    vi.mocked(api.listTokens).mockResolvedValue([]);
    vi.spyOn(window, "prompt").mockReturnValue(null);

    render(<TokensPage />);
    await screen.findByText("No reviewer tokens yet.");
    await userEvent.type(screen.getByPlaceholderText("alex-laptop"), "alex-phone");
    await userEvent.click(screen.getByRole("button", { name: "Create token" }));

    expect(api.createToken).not.toHaveBeenCalled();
  });

  it("disables the create button while a reveal is pending, so a second create cannot overwrite it", async () => {
    // The disabled attribute is the *only* guard here, so this asserts it
    // directly rather than trying to drive a second submit. An earlier version
    // of this test claimed Enter could still submit past it; that is false per
    // HTML implicit submission (the sole submit button is disabled), which made
    // the test vacuous and the handler-side guard it claimed to pin dead code.
    // Found by independent review.
    vi.mocked(api.listTokens).mockResolvedValue([]);
    vi.mocked(api.createToken).mockResolvedValue(sampleCreated);

    render(<TokensPage />);
    await createAndReveal();

    expect(screen.getByRole("button", { name: "Create token" })).toBeDisabled();
    expect(api.createToken).toHaveBeenCalledTimes(1);
  });

  it("keeps the revealed credential when the dismiss confirmation is declined", async () => {
    vi.mocked(api.listTokens).mockResolvedValue([]);
    vi.mocked(api.createToken).mockResolvedValue(sampleCreated);

    render(<TokensPage />);
    await createAndReveal();

    vi.mocked(window.confirm).mockReturnValue(false);
    await userEvent.click(screen.getByRole("button", { name: "Dismiss" }));

    expect(screen.getByDisplayValue("plaintext-bearer-token")).toBeInTheDocument();
  });

  it("dismisses the revealed token once the confirmation is accepted", async () => {
    vi.mocked(api.listTokens).mockResolvedValue([]);
    vi.mocked(api.createToken).mockResolvedValue(sampleCreated);

    render(<TokensPage />);
    await createAndReveal();

    await userEvent.click(screen.getByRole("button", { name: "Dismiss" }));

    expect(screen.queryByDisplayValue("plaintext-bearer-token")).not.toBeInTheDocument();
  });

  it("reports reveal state so the shell can block navigation away from it", async () => {
    // The page cannot veto its own unmount, and a tab switch would discard the
    // only copy of the credential — App blocks on this signal.
    const onRevealChange = vi.fn();
    vi.mocked(api.listTokens).mockResolvedValue([]);
    vi.mocked(api.createToken).mockResolvedValue(sampleCreated);

    render(<TokensPage onRevealChange={onRevealChange} />);
    await createAndReveal();

    expect(onRevealChange).toHaveBeenLastCalledWith(true);

    await userEvent.click(screen.getByRole("button", { name: "Dismiss" }));
    expect(onRevealChange).toHaveBeenLastCalledWith(false);
  });

  it("reports reveal-pending as soon as creation is submitted, not only once it resolves", async () => {
    // A tab switch between submit and response used to slip past this guard
    // entirely: the request was in flight, justCreated was still null, so
    // nothing blocked the unmount and the response landed on a hook that no
    // longer existed. Found in review (chatgpt-codex-connector).
    const onRevealChange = vi.fn();
    let resolveCreate!: (token: CreatedReviewerToken) => void;
    vi.mocked(api.listTokens).mockResolvedValue([]);
    vi.mocked(api.createToken).mockReturnValue(new Promise((resolve) => (resolveCreate = resolve)));

    render(<TokensPage onRevealChange={onRevealChange} />);
    await screen.findByText("No reviewer tokens yet.");
    await userEvent.type(screen.getByPlaceholderText("alex-laptop"), "alex-phone");
    await userEvent.click(screen.getByRole("button", { name: "Create token" }));

    expect(onRevealChange).toHaveBeenLastCalledWith(true);

    await act(async () => resolveCreate(sampleCreated));
    expect(onRevealChange).toHaveBeenLastCalledWith(true);
  });

  it("prevents reload/close while a reveal is pending, and stops once it is dismissed", async () => {
    vi.mocked(api.listTokens).mockResolvedValue([]);
    vi.mocked(api.createToken).mockResolvedValue(sampleCreated);

    render(<TokensPage />);
    await createAndReveal();

    let unloadEvent = new Event("beforeunload", { cancelable: true });
    window.dispatchEvent(unloadEvent);
    expect(unloadEvent.defaultPrevented).toBe(true);

    await userEvent.click(screen.getByRole("button", { name: "Dismiss" }));

    unloadEvent = new Event("beforeunload", { cancelable: true });
    window.dispatchEvent(unloadEvent);
    expect(unloadEvent.defaultPrevented).toBe(false);
  });

  it("does not revoke when the confirmation is declined", async () => {
    vi.mocked(api.listTokens).mockResolvedValue([sampleToken]);

    render(<TokensPage />);
    await screen.findByText("alex-laptop");

    vi.mocked(window.confirm).mockReturnValue(false);
    await userEvent.click(screen.getByRole("button", { name: "Revoke" }));

    expect(api.revokeToken).not.toHaveBeenCalled();
    expect(screen.getByText("active")).toBeInTheDocument();
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

  it("marks a self-revoked token revoked even when the follow-up refresh 401s", async () => {
    // Revoking the token this browser authenticates with invalidates it
    // immediately, so the refresh the revoke triggers deterministically 401s.
    // If the dashboard relied on that refresh alone, it would keep showing
    // the just-revoked token as active with a live Revoke button. Found in
    // review (chatgpt-codex-connector).
    vi.mocked(api.listTokens)
      .mockResolvedValueOnce([sampleToken])
      .mockRejectedValueOnce(new ApiError(401, "unauthorized"));
    vi.mocked(api.revokeToken).mockResolvedValue(undefined);

    render(<TokensPage />);
    await screen.findByText("active");

    await userEvent.click(screen.getByRole("button", { name: "Revoke" }));

    expect(await screen.findByText("revoked")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Revoke" })).not.toBeInTheDocument();
  });
});
