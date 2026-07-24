import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { GrantsPage } from "./Grants";
import { api } from "../api/client";
import type { Grant } from "../api/client";

vi.mock("../api/client", async () => {
  const actual = await vi.importActual<typeof import("../api/client")>("../api/client");
  return {
    ...actual,
    api: {
      listGrants: vi.fn(),
      createGrant: vi.fn(),
      revokeGrant: vi.fn(),
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

// Approve/revoke/create are all gated on a non-empty reviewer name now (see
// Grants.tsx) — every test that exercises one of those buttons fills this in
// first, same as it fills in the scopes field.
async function fillReviewer(name = "reviewer-a") {
  await userEvent.type(screen.getByLabelText("Reviewer name"), name);
}

describe("GrantsPage", () => {
  // Without this, assertions like toHaveBeenCalled() can pass because of a call
  // left over from a previous test, not because this test's own render triggered
  // one — making the suite's pass/fail depend on run order. Found in review.
  beforeEach(() => {
    vi.clearAllMocks();
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

    await fillReviewer();
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

    await fillReviewer();
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

    await fillReviewer();
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

    await fillReviewer();
    await userEvent.type(
      screen.getByPlaceholderText("identity.basic, projects.spritz.read"),
      " identity.basic , projects.spritz.read ",
    );
    await userEvent.type(screen.getByLabelText(/TTL/), "5");
    await userEvent.click(screen.getByRole("button", { name: "Create grant" }));

    await waitFor(() => expect(api.createGrant).toHaveBeenCalled());
    expect(api.createGrant).toHaveBeenCalledWith(
      "agent-a",
      ["identity.basic", "projects.spritz.read"],
      "facts",
      "reviewer-a",
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

    await fillReviewer();
    await userEvent.type(screen.getByPlaceholderText("identity.basic, projects.spritz.read"), "identity.basic");
    const submitButton = screen.getByRole("button", { name: "Create grant" });
    await userEvent.click(submitButton);

    expect(submitButton).toBeDisabled();

    resolveCreate(sampleGrant);
    await waitFor(() => expect(submitButton).not.toBeDisabled());
  });

  it("disables Create grant and Revoke until a reviewer name is entered", async () => {
    vi.mocked(api.listGrants).mockResolvedValue([sampleGrant]);

    render(<GrantsPage />);
    await screen.findByText("identity.basic");

    expect(screen.getByRole("button", { name: "Create grant" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Revoke" })).toBeDisabled();

    await fillReviewer();

    expect(screen.getByRole("button", { name: "Create grant" })).not.toBeDisabled();
    expect(screen.getByRole("button", { name: "Revoke" })).not.toBeDisabled();
  });

  it("removes a grant from the list after revoking it", async () => {
    vi.mocked(api.listGrants).mockResolvedValueOnce([sampleGrant]).mockResolvedValueOnce([]);
    vi.mocked(api.revokeGrant).mockResolvedValue(undefined);

    render(<GrantsPage />);
    await screen.findByText("identity.basic");

    await fillReviewer();
    await userEvent.click(screen.getByRole("button", { name: "Revoke" }));

    await waitFor(() => {
      expect(screen.getByText("No grants for this subject.")).toBeInTheDocument();
    });
    expect(api.revokeGrant).toHaveBeenCalledWith("grant-1", "reviewer-a");
  });
});
