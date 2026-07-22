import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { StagedDiffsPage } from "./StagedDiffs";
import { api } from "../api/client";
import type { StagedDiff } from "../api/client";

vi.mock("../api/client", async () => {
  const actual = await vi.importActual<typeof import("../api/client")>("../api/client");
  return {
    ...actual,
    api: {
      listStagedDiffs: vi.fn(),
      approveStagedDiff: vi.fn(),
      rejectStagedDiff: vi.fn(),
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

describe("StagedDiffsPage", () => {
  it("renders pending diffs with their dedupe verdict", async () => {
    vi.mocked(api.listStagedDiffs).mockResolvedValue([sampleDiff]);

    render(<StagedDiffsPage />);

    expect(await screen.findByText("user prefers flat whites")).toBeInTheDocument();
    expect(screen.getByText("Novel")).toBeInTheDocument();
    expect(screen.getByText("preferences.coffee")).toBeInTheDocument();
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
    expect(api.approveStagedDiff).toHaveBeenCalledWith("diff-1", "dashboard-reviewer");
  });
});
