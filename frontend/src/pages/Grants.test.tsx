import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { GrantsPage } from "./Grants";
import { api, ApiError } from "../api/client";
import type { Grant, GrantRequest } from "../api/client";

vi.mock("../api/client", async () => {
  const actual = await vi.importActual<typeof import("../api/client")>("../api/client");
  return {
    ...actual,
    api: {
      listGrants: vi.fn(),
      createGrant: vi.fn(),
      revokeGrant: vi.fn(),
      listGrantRequests: vi.fn(),
      approveGrantRequest: vi.fn(),
      denyGrantRequest: vi.fn(),
    },
  };
});

const sampleGrant: Grant = {
  id: "grant-1",
  subject: "agent-a",
  scopes: ["identity.basic"],
  depth: "facts",
  active: true,
  created_at: "2026-07-23T00:00:00Z",
};

const sampleGrantRequest: GrantRequest = {
  id: "req-1",
  subject: "agent-c",
  requested_scopes: ["identity.basic"],
  depth: "facts",
  requested_ttl_seconds: 3600,
  justification: "need this to greet the user by name",
  status: "pending",
  created_at: "2026-07-26T00:00:00Z",
};

describe("GrantsPage", () => {
  // Without this, assertions like toHaveBeenCalled() can pass because of a call
  // left over from a previous test, not because this test's own render triggered
  // one — making the suite's pass/fail depend on run order. Found in review.
  beforeEach(() => {
    vi.clearAllMocks();
    // Every test renders GrantsPage, which now always fetches pending grant
    // requests alongside the subject's grants — default to none so existing
    // tests that don't care about requests aren't left with an unresolved
    // promise (a bare vi.fn() call returns undefined, not a Promise).
    vi.mocked(api.listGrantRequests).mockResolvedValue([]);
  });

  it("renders grants for the default subject", async () => {
    vi.mocked(api.listGrants).mockResolvedValue([sampleGrant]);

    render(<GrantsPage />);

    expect(await screen.findByText("identity.basic")).toBeInTheDocument();
  });

  it("rejects a non-numeric TTL instead of silently creating a permanent grant", async () => {
    vi.mocked(api.listGrants).mockResolvedValue([]);

    render(<GrantsPage />);
    await waitFor(() => expect(api.listGrants).toHaveBeenCalled());

    await userEvent.type(screen.getByPlaceholderText("identity.basic, projects.spritz.read"), "identity.basic");
    await userEvent.type(screen.getByLabelText(/TTL/), "not-a-number");
    await userEvent.click(screen.getByRole("button", { name: "Create grant" }));

    expect(await screen.findByText(/TTL must be a positive whole number/)).toBeInTheDocument();
    // The regression this guards against: NaN * 60 -> NaN -> JSON.stringify(NaN)
    // is `null` -> the backend would treat that as "no expiry" -> a typo silently
    // creates a permanent grant. createGrant must never be called with bad input.
    expect(api.createGrant).not.toHaveBeenCalled();
  });

  it("rejects a decimal TTL that wouldn't convert to a whole number of seconds", async () => {
    vi.mocked(api.listGrants).mockResolvedValue([]);
    render(<GrantsPage />);
    await waitFor(() => expect(api.listGrants).toHaveBeenCalled());

    await userEvent.type(screen.getByPlaceholderText("identity.basic, projects.spritz.read"), "identity.basic");
    await userEvent.type(screen.getByLabelText(/TTL/), "0.1");
    await userEvent.click(screen.getByRole("button", { name: "Create grant" }));

    expect(await screen.findByText(/TTL must be a positive whole number/)).toBeInTheDocument();
    expect(api.createGrant).not.toHaveBeenCalled();
  });

  it("rejects a zero or negative TTL", async () => {
    vi.mocked(api.listGrants).mockResolvedValue([]);
    render(<GrantsPage />);
    await waitFor(() => expect(api.listGrants).toHaveBeenCalled());

    await userEvent.type(screen.getByPlaceholderText("identity.basic, projects.spritz.read"), "identity.basic");
    await userEvent.type(screen.getByLabelText(/TTL/), "-5");
    await userEvent.click(screen.getByRole("button", { name: "Create grant" }));

    expect(await screen.findByText(/TTL must be a positive whole number/)).toBeInTheDocument();
    expect(api.createGrant).not.toHaveBeenCalled();
  });

  it("submits a valid grant with scopes trimmed and TTL converted to seconds", async () => {
    vi.mocked(api.listGrants).mockResolvedValue([]);
    vi.mocked(api.createGrant).mockResolvedValue(sampleGrant);

    render(<GrantsPage />);
    await waitFor(() => expect(api.listGrants).toHaveBeenCalled());

    await userEvent.type(
      screen.getByPlaceholderText("identity.basic, projects.spritz.read"),
      " identity.basic , projects.spritz.read ",
    );
    await userEvent.type(screen.getByLabelText(/TTL/), "5");
    await userEvent.click(screen.getByRole("button", { name: "Create grant" }));

    await waitFor(() => expect(api.createGrant).toHaveBeenCalled());
    // approved_by is no longer a client-supplied argument — it's derived
    // server-side from the authenticated reviewer token (see internal/api's
    // package comment).
    expect(api.createGrant).toHaveBeenCalledWith(
      "agent-a",
      ["identity.basic", "projects.spritz.read"],
      "facts",
      300,
    );
  });

  it("disables the submit button while a create request is in flight", async () => {
    vi.mocked(api.listGrants).mockResolvedValue([]);
    let resolveCreate: (g: Grant) => void = () => {};
    vi.mocked(api.createGrant).mockReturnValue(
      new Promise((resolve) => {
        resolveCreate = resolve;
      }),
    );

    render(<GrantsPage />);
    await waitFor(() => expect(api.listGrants).toHaveBeenCalled());

    await userEvent.type(screen.getByPlaceholderText("identity.basic, projects.spritz.read"), "identity.basic");
    const submitButton = screen.getByRole("button", { name: "Create grant" });
    await userEvent.click(submitButton);

    expect(submitButton).toBeDisabled();

    resolveCreate(sampleGrant);
    await waitFor(() => expect(submitButton).not.toBeDisabled());
  });

  it("removes a grant from the list after revoking it", async () => {
    vi.mocked(api.listGrants).mockResolvedValueOnce([sampleGrant]).mockResolvedValueOnce([]);
    vi.mocked(api.revokeGrant).mockResolvedValue(undefined);

    render(<GrantsPage />);
    await screen.findByText("identity.basic");

    await userEvent.click(screen.getByRole("button", { name: "Revoke" }));

    await waitFor(() => {
      expect(screen.getByText("No grants for this subject.")).toBeInTheDocument();
    });
    // revoked_by is no longer a client-supplied argument — derived server-side.
    expect(api.revokeGrant).toHaveBeenCalledWith("grant-1");
  });

  it("shows pending grant requests from any subject and removes one after approving it", async () => {
    vi.mocked(api.listGrants).mockResolvedValue([]);
    // Once for the initial render, then empty for the refetch decideRequest
    // triggers after a successful decision (a real backend would no longer
    // return an approved request from ?status=pending).
    vi.mocked(api.listGrantRequests).mockResolvedValueOnce([sampleGrantRequest]).mockResolvedValue([]);
    vi.mocked(api.approveGrantRequest).mockResolvedValue(sampleGrant);

    render(<GrantsPage />);

    expect(await screen.findByText("from agent-c")).toBeInTheDocument();
    expect(screen.getByText("need this to greet the user by name")).toBeInTheDocument();

    await userEvent.click(screen.getByRole("button", { name: "Approve" }));

    await waitFor(() => {
      expect(screen.queryByText("from agent-c")).not.toBeInTheDocument();
    });
    expect(api.approveGrantRequest).toHaveBeenCalledWith("req-1");
  });

  it("removes a grant request from the list after denying it", async () => {
    vi.mocked(api.listGrants).mockResolvedValue([]);
    vi.mocked(api.listGrantRequests).mockResolvedValueOnce([sampleGrantRequest]).mockResolvedValue([]);
    vi.mocked(api.denyGrantRequest).mockResolvedValue(undefined);

    render(<GrantsPage />);
    await screen.findByText("from agent-c");

    await userEvent.click(screen.getByRole("button", { name: "Deny" }));

    await waitFor(() => {
      expect(screen.queryByText("from agent-c")).not.toBeInTheDocument();
    });
    expect(api.denyGrantRequest).toHaveBeenCalledWith("req-1");
  });

  // Regression test for the review finding (flagged independently by two
  // reviewers): the grants list and the grant-requests list load via two
  // separate, independently-resolving effects. A shared error state meant a
  // grant-requests failure could be silently erased by an unrelated grants
  // success landing afterward — the operator would see no pending requests
  // and no explanation why.
  it("keeps the grant-requests load error visible even after the grants load succeeds", async () => {
    // Forces the exact ordering the bug depended on, rather than trusting
    // two immediately-resolving promises to interleave the right way by
    // accident (flagged in review: the original version of this test could
    // pass even against the buggy shared-error-state implementation,
    // depending on microtask scheduling). listGrants is held open until
    // after the grant-requests error is already on screen, then resolved —
    // if the two effects still shared error state, that resolution would
    // clear the banner we just asserted is there.
    let resolveGrants: (g: Grant[]) => void = () => {};
    vi.mocked(api.listGrants).mockReturnValue(
      new Promise((resolve) => {
        resolveGrants = resolve;
      }),
    );
    vi.mocked(api.listGrantRequests).mockRejectedValue(new ApiError(500, "could not list grant requests"));

    render(<GrantsPage />);

    expect(await screen.findByText("could not list grant requests")).toBeInTheDocument();

    resolveGrants([]);

    // Wait for the grants promise to actually flow through its effect and
    // update the DOM (the empty-grants message only appears once that
    // state update has landed) before re-asserting the error is untouched —
    // just awaiting the mock having been *called* would prove nothing, since
    // that already happened at the initial render, before resolveGrants ran.
    await screen.findByText("No grants for this subject.");
    expect(screen.getByText("could not list grant requests")).toBeInTheDocument();
  });
});
