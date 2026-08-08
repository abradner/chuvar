// Pure presenter tests: no vi.mock, no async setup, no API in sight — props in,
// DOM out. This file is the concrete payoff of the hook/view split (AGENTS.md
// §6, "UI component standard"): everything here would otherwise need the full
// mocked-API harness Tokens.test.tsx carries. Behaviour that involves the hook
// (fetching, confirms, the reveal lifecycle) is covered there, through the
// page; this file covers only what rendering does with given props.
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { TokensView, type TokensViewProps } from "./TokensView";
import { enrollmentSecret } from "./enrollmentSecret";

const noProps: TokensViewProps = {
  tokens: [],
  loadError: null,
  error: null,
  busyId: null,
  creating: false,
  justCreated: null,
  onCreate: vi.fn().mockResolvedValue(true),
  onDismissReveal: vi.fn(),
  onRevoke: vi.fn(),
};

const created = {
  id: "token-2",
  label: "alex-phone",
  active: true,
  created_at: "2026-08-07T00:00:00Z",
  token: "plaintext-bearer-token",
  totp_enroll_uri: "otpauth://totp/Chuvar:alex-phone?secret=JBSWY3DPEHPK3PXP&issuer=Chuvar",
};

describe("TokensView", () => {
  it("renders the reveal panel with the parsed setup key when justCreated is set", () => {
    render(<TokensView {...noProps} justCreated={created} />);

    expect(screen.getByDisplayValue("plaintext-bearer-token")).toBeInTheDocument();
    expect(screen.getByDisplayValue("JBSWY3DPEHPK3PXP")).toBeInTheDocument();
  });

  it("disables the create button while a reveal is pending", () => {
    render(<TokensView {...noProps} justCreated={created} />);

    expect(screen.getByRole("button", { name: "Create token" })).toBeDisabled();
  });

  it("disables the create button while creating", () => {
    render(<TokensView {...noProps} creating={true} />);

    expect(screen.getByRole("button", { name: "Create token" })).toBeDisabled();
  });

  it("clears the label field only when onCreate reports success", async () => {
    const onCreate = vi.fn().mockResolvedValue(false);
    render(<TokensView {...noProps} onCreate={onCreate} />);

    const label = screen.getByPlaceholderText("alex-laptop");
    await userEvent.type(label, "alex-phone");
    await userEvent.click(screen.getByRole("button", { name: "Create token" }));

    expect(onCreate).toHaveBeenCalledWith("alex-phone");
    // A failed create keeps the typed label so the operator can retry
    // without retyping.
    expect(label).toHaveValue("alex-phone");
  });

  it("shows no revoke button on an already-revoked token", () => {
    render(
      <TokensView
        {...noProps}
        tokens={[
          { id: "t1", label: "old-phone", active: false, created_at: "2026-07-01T00:00:00Z", revoked_at: "2026-08-01T00:00:00Z" },
        ]}
      />,
    );

    expect(screen.getByText("revoked")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Revoke" })).not.toBeInTheDocument();
  });
});

describe("enrollmentSecret", () => {
  it("extracts the secret from a well-formed otpauth URI", () => {
    expect(enrollmentSecret("otpauth://totp/X?secret=ABC123&issuer=Chuvar")).toBe("ABC123");
  });

  it("falls back to the raw value on an unparseable URI", () => {
    expect(enrollmentSecret("not a valid uri")).toBe("not a valid uri");
  });

  it("falls back to the raw URI on an empty secret param", () => {
    // searchParams.get returns "" (not null) for `?secret=` — a `??` fallback
    // misses this and blanks the field. Found in review.
    expect(enrollmentSecret("otpauth://totp/X?secret=&issuer=Chuvar")).toBe("otpauth://totp/X?secret=&issuer=Chuvar");
  });
});
