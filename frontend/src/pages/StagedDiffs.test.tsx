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
    expect(api.approveStagedDiff).toHaveBeenCalledWith("diff-1");
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
