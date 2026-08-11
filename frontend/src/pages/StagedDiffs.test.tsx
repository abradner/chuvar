import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { StagedDiffsPage } from "./StagedDiffs";
import { api } from "../api/client";
import type { Fact, StagedDiff } from "../api/client";

vi.mock("../api/client", async () => {
  const actual = await vi.importActual<typeof import("../api/client")>("../api/client");
  return {
    ...actual,
    api: {
      listStagedDiffs: vi.fn(),
      approveStagedDiff: vi.fn(),
      rejectStagedDiff: vi.fn(),
      getFact: vi.fn(),
      webauthnAssertBegin: vi.fn(),
    },
  };
});

const sampleDiff: StagedDiff = {
  id: "diff-1",
  subject: "agent-a",
  content: "user prefers flat whites",
  proposed_scopes: ["preferences.coffee"],
  status: "pending",
  dedupe_verdict: "novel",
  created_at: "2026-07-23T00:00:00Z",
};

const sampleTargetFact: Fact = {
  id: "fact-1",
  content: "user prefers oat milk lattes",
  scopes: ["preferences.coffee"],
  created_at: "2026-07-20T00:00:00Z",
  valid_at: "2026-07-20T00:00:00Z",
};

describe("StagedDiffsPage", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    // Approve prompts for the TOTP second factor via window.prompt — see
    // Grants.test.tsx's identical setup for why.
    vi.spyOn(window, "prompt").mockReturnValue("123456");
  });

  it("renders pending diffs with their dedupe verdict and proposer", async () => {
    vi.mocked(api.listStagedDiffs).mockResolvedValue([sampleDiff]);

    render(<StagedDiffsPage />);

    expect(await screen.findByText("user prefers flat whites")).toBeInTheDocument();
    expect(screen.getByText("Novel")).toBeInTheDocument();
    expect(screen.getByText("preferences.coffee")).toBeInTheDocument();
    expect(screen.getByText("from agent-a")).toBeInTheDocument();
  });

  it("shows an empty state when nothing is pending", async () => {
    vi.mocked(api.listStagedDiffs).mockResolvedValue([]);

    render(<StagedDiffsPage />);

    expect(await screen.findByText("Nothing waiting for review.")).toBeInTheDocument();
  });

  it("removes a diff from the list after approving it", async () => {
    vi.mocked(api.listStagedDiffs).mockResolvedValue([sampleDiff]);
    vi.mocked(api.approveStagedDiff).mockResolvedValue(undefined);

    render(<StagedDiffsPage />);
    await screen.findByText("user prefers flat whites");

    await userEvent.click(screen.getByRole("button", { name: "Approve" }));

    await waitFor(() => {
      expect(screen.queryByText("user prefers flat whites")).not.toBeInTheDocument();
    });
    // decided_by is no longer a client-supplied argument — it's derived
    // server-side from the authenticated reviewer token (see internal/api's
    // package comment).
    expect(api.approveStagedDiff).toHaveBeenCalledWith("diff-1", { totpCode: "123456" });
  });

  it("approves with a passkey assertion when the prompt is left blank and the browser supports WebAuthn", async () => {
    vi.mocked(api.listStagedDiffs).mockResolvedValue([sampleDiff]);
    vi.mocked(api.approveStagedDiff).mockResolvedValue(undefined);
    vi.mocked(window.prompt).mockReturnValue("");
    // jsdom implements neither the Credential Management nor WebAuthn APIs —
    // stub the boundary so promptSecondFactor's real passkey branch runs.
    Object.defineProperty(window, "PublicKeyCredential", {
      value: function PublicKeyCredential() {},
      writable: true,
      configurable: true,
    });
    Object.defineProperty(navigator, "credentials", {
      value: {
        get: vi.fn().mockResolvedValue({
          id: "cred-1",
          rawId: new Uint8Array([1]).buffer,
          type: "public-key",
          response: {
            clientDataJSON: new Uint8Array([2]).buffer,
            authenticatorData: new Uint8Array([3]).buffer,
            signature: new Uint8Array([4]).buffer,
          },
        }),
      },
      writable: true,
      configurable: true,
    });
    vi.mocked(api.webauthnAssertBegin).mockResolvedValue({
      publicKey: { challenge: "AAAA" },
    });

    render(<StagedDiffsPage />);
    await screen.findByText("user prefers flat whites");
    await userEvent.click(screen.getByRole("button", { name: "Approve" }));

    await waitFor(() => {
      expect(api.approveStagedDiff).toHaveBeenCalledWith("diff-1", { webauthnAssertion: expect.any(String) });
    });

    Reflect.deleteProperty(window, "PublicKeyCredential");
    Reflect.deleteProperty(navigator, "credentials");
  });

  it("does not approve a diff when the TOTP prompt is cancelled", async () => {
    vi.mocked(api.listStagedDiffs).mockResolvedValue([sampleDiff]);
    // window.prompt is already spied in beforeEach — re-spying here (rather
    // than adjusting the existing spy's return value) would stack a second
    // spy on top of it. Found in review.
    vi.mocked(window.prompt).mockReturnValue(null);

    render(<StagedDiffsPage />);
    await screen.findByText("user prefers flat whites");

    await userEvent.click(screen.getByRole("button", { name: "Approve" }));

    expect(api.approveStagedDiff).not.toHaveBeenCalled();
  });

  it("shows the target fact's current content for a diff that supersedes one, and blocks approval until it loads", async () => {
    const diffWithTarget: StagedDiff = { ...sampleDiff, target_fact_id: "fact-1" };
    vi.mocked(api.listStagedDiffs).mockResolvedValue([diffWithTarget]);
    let resolveGetFact: (f: Fact) => void = () => {};
    vi.mocked(api.getFact).mockReturnValue(
      new Promise((resolve) => {
        resolveGetFact = resolve;
      }),
    );

    render(<StagedDiffsPage />);
    await screen.findByText("user prefers flat whites");

    expect(screen.getByText("This replaces an existing fact:")).toBeInTheDocument();
    // findByText (not getByText): the target-fact fetch effect runs in a
    // follow-up render after the diffs list itself commits, so this text isn't
    // guaranteed to be in the DOM the instant the assertion above returns.
    expect(await screen.findByText("Loading target fact…")).toBeInTheDocument();
    // The whole point: a target that hasn't resolved yet must not be approvable —
    // approving blind on an unconfirmed replacement is the exact risk this UI
    // exists to prevent.
    expect(screen.getByRole("button", { name: "Approve" })).toBeDisabled();

    resolveGetFact(sampleTargetFact);

    await waitFor(() => {
      expect(screen.getByText("user prefers oat milk lattes")).toBeInTheDocument();
    });
    expect(screen.getByRole("button", { name: "Approve" })).not.toBeDisabled();
  });
});
