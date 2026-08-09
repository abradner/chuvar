// Pure presenter tests: no vi.mock, no async harness — props in, DOM out.
// Mirrors TokensView.test.tsx's shape (AGENTS.md §6's "UI component
// standard" payoff): everything here would otherwise need the full
// navigator.credentials + mocked-API harness Passkeys.test.tsx carries.
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { PasskeysView, type PasskeysViewProps } from "./PasskeysView";

const noProps: PasskeysViewProps = {
  credentials: [],
  loading: false,
  loadError: null,
  error: null,
  busyId: null,
  registering: false,
  supported: true,
  onRegister: vi.fn().mockResolvedValue(true),
  onRevoke: vi.fn(),
};

describe("PasskeysView", () => {
  it("shows the unsupported message and hides the enrollment form when the browser lacks WebAuthn", () => {
    render(<PasskeysView {...noProps} supported={false} />);

    expect(screen.getByText("This browser does not support passkeys (WebAuthn).")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Add passkey" })).not.toBeInTheDocument();
  });

  it("shows a loading indicator instead of the empty state while the list is loading", () => {
    render(<PasskeysView {...noProps} loading={true} />);

    expect(screen.getByText("Loading passkeys…")).toBeInTheDocument();
    expect(screen.queryByText("No passkeys enrolled yet.")).not.toBeInTheDocument();
  });

  it("does not show the empty state alongside a load error", () => {
    render(<PasskeysView {...noProps} loading={false} loadError="boom" />);

    expect(screen.getByText("boom")).toBeInTheDocument();
    expect(screen.queryByText("No passkeys enrolled yet.")).not.toBeInTheDocument();
  });

  it("renders enrolled credentials with their active state", () => {
    render(
      <PasskeysView
        {...noProps}
        credentials={[
          { id: "c1", label: "yubikey", active: true, attestation_type: "none", created_at: "2026-08-09T00:00:00Z" },
        ]}
      />,
    );

    expect(screen.getByText("yubikey")).toBeInTheDocument();
    expect(screen.getByText("active")).toBeInTheDocument();
  });

  it("shows no revoke button on an already-revoked credential", () => {
    render(
      <PasskeysView
        {...noProps}
        credentials={[
          {
            id: "c1",
            label: "old-key",
            active: false,
            attestation_type: "none",
            created_at: "2026-07-01T00:00:00Z",
            revoked_at: "2026-08-01T00:00:00Z",
          },
        ]}
      />,
    );

    expect(screen.getByText("revoked")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Revoke" })).not.toBeInTheDocument();
  });

  it("surfaces a clone-warning credential distinctly, even while still technically 'active' momentarily", () => {
    // In practice a clone-flagged credential is also revoked (fail-closed —
    // see backend's FlagWebAuthnCredentialCloneWarning), but the view renders
    // whatever CloneWarningAt/Active it's given rather than assuming the two
    // always arrive together, so this pins the warning text independent of
    // the active flag.
    render(
      <PasskeysView
        {...noProps}
        credentials={[
          {
            id: "c1",
            label: "cloned-key",
            active: false,
            attestation_type: "none",
            created_at: "2026-07-01T00:00:00Z",
            clone_warning_at: "2026-08-01T00:00:00Z",
          },
        ]}
      />,
    );

    expect(screen.getByText(/POSSIBLE CLONE DETECTED/)).toBeInTheDocument();
  });

  it("disables the add-passkey button while registering", () => {
    render(<PasskeysView {...noProps} registering={true} />);

    expect(screen.getByRole("button", { name: "Waiting for authenticator…" })).toBeDisabled();
  });

  it("clears the label field only when onRegister reports success", async () => {
    const onRegister = vi.fn().mockResolvedValue(false);
    render(<PasskeysView {...noProps} onRegister={onRegister} />);

    const label = screen.getByPlaceholderText("yubikey-5c");
    await userEvent.type(label, "my-key");
    await userEvent.click(screen.getByRole("button", { name: "Add passkey" }));

    expect(onRegister).toHaveBeenCalledWith("my-key");
    expect(label).toHaveValue("my-key");
  });

  it("calls onRevoke with the credential id and label", async () => {
    const onRevoke = vi.fn();
    render(
      <PasskeysView
        {...noProps}
        onRevoke={onRevoke}
        credentials={[
          { id: "c1", label: "yubikey", active: true, attestation_type: "none", created_at: "2026-08-09T00:00:00Z" },
        ]}
      />,
    );

    await userEvent.click(screen.getByRole("button", { name: "Revoke" }));

    expect(onRevoke).toHaveBeenCalledWith("c1", "yubikey");
  });
});
