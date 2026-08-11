// Behavioral tests: hook + view integrated, exercised through TokensPage
// (AGENTS.md §6 — "Behavioral tests exercise the page"). Mocks api/client
// (the trust/network boundary) and stubs navigator.credentials/
// PublicKeyCredential (the browser boundary jsdom doesn't implement) —
// neither is the thing under test, both are what let the real hook logic run.
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { TokensPage } from "./Tokens";
import { bufferToBase64url } from "./webauthnCodec";
import { api, ApiError } from "../../api/client";
import type { CredentialCreationOptionsJSON, CredentialRequestOptionsJSON, WebAuthnCredential } from "../../api/client";

vi.mock("../../api/client", async () => {
  const actual = await vi.importActual<typeof import("../../api/client")>("../../api/client");
  return {
    ...actual,
    api: {
      // TokensView's own half of the page — present so TokensPage's other
      // hook doesn't throw; every test here points it at an empty inventory
      // and never asserts on it.
      listTokens: vi.fn().mockResolvedValue([]),
      createToken: vi.fn(),
      revokeToken: vi.fn(),
      listWebAuthnCredentials: vi.fn(),
      webauthnRegisterBegin: vi.fn(),
      webauthnRegisterFinish: vi.fn(),
      webauthnAssertBegin: vi.fn(),
      revokeWebAuthnCredential: vi.fn(),
    },
  };
});

function sampleCreationOptions(): CredentialCreationOptionsJSON {
  return {
    publicKey: {
      rp: { id: "localhost", name: "Chuvar Test" },
      user: { id: bufferToBase64url(new Uint8Array([1]).buffer), name: "test-reviewer", displayName: "test-reviewer" },
      challenge: bufferToBase64url(new Uint8Array([9, 9]).buffer),
      pubKeyCredParams: [{ type: "public-key", alg: -7 }],
    },
  };
}

function sampleRequestOptions(): CredentialRequestOptionsJSON {
  return {
    publicKey: {
      challenge: bufferToBase64url(new Uint8Array([7, 7]).buffer),
      rpId: "localhost",
      allowCredentials: [{ type: "public-key", id: bufferToBase64url(new Uint8Array([2]).buffer) }],
    },
  };
}

function fakeAttestationCredential(id = "new-cred-id"): PublicKeyCredential {
  return {
    id,
    rawId: new Uint8Array([1, 2, 3]).buffer,
    type: "public-key",
    response: {
      clientDataJSON: new Uint8Array([4]).buffer,
      attestationObject: new Uint8Array([5, 6]).buffer,
    },
  } as unknown as PublicKeyCredential;
}

function fakeAssertionCredential(): PublicKeyCredential {
  return {
    id: "existing-cred-id",
    rawId: new Uint8Array([9]).buffer,
    type: "public-key",
    response: {
      clientDataJSON: new Uint8Array([1]).buffer,
      authenticatorData: new Uint8Array([2]).buffer,
      signature: new Uint8Array([3]).buffer,
    },
  } as unknown as PublicKeyCredential;
}

const activeCredential: WebAuthnCredential = {
  id: "cred-1",
  label: "yubikey",
  active: true,
  attestation_type: "none",
  created_at: "2026-08-09T00:00:00Z",
};

// stubWebAuthnSupport makes browserSupportsPasskeys() (usePasskeys.ts) read
// true, and gives the test control of navigator.credentials.create/.get —
// jsdom implements neither the Credential Management nor WebAuthn APIs.
function stubWebAuthnSupport() {
  Object.defineProperty(window, "PublicKeyCredential", {
    value: function PublicKeyCredential() {},
    writable: true,
    configurable: true,
  });
  Object.defineProperty(navigator, "credentials", {
    value: { create: vi.fn(), get: vi.fn() },
    writable: true,
    configurable: true,
  });
}

function unstubWebAuthnSupport() {
  Reflect.deleteProperty(window, "PublicKeyCredential");
  Reflect.deleteProperty(navigator, "credentials");
}

describe("TokensPage (Passkeys section) — unsupported browser", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("shows the unsupported message and never calls listWebAuthnCredentials when the browser lacks WebAuthn", async () => {
    // No stubWebAuthnSupport() here: this is jsdom's real (WebAuthn-less)
    // default, the case every other existing Tokens.test.tsx test already
    // silently runs under.
    render(<TokensPage />);

    expect(await screen.findByText("This browser does not support passkeys (WebAuthn).")).toBeInTheDocument();
    expect(api.listWebAuthnCredentials).not.toHaveBeenCalled();
  });
});

describe("TokensPage (Passkeys section) — supported browser", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    stubWebAuthnSupport();
    // A valid-shaped TOTP code: registration of a device's first passkey
    // always requires one (requireExistingSecondFactor has no factorless
    // path), so most tests here just need the prompt to produce something.
    vi.spyOn(window, "prompt").mockReturnValue("123456");
    vi.spyOn(window, "confirm").mockReturnValue(true);
  });

  afterEach(() => {
    unstubWebAuthnSupport();
  });

  it("lists enrolled passkeys", async () => {
    vi.mocked(api.listWebAuthnCredentials).mockResolvedValue([activeCredential]);

    render(<TokensPage />);

    expect(await screen.findByText("yubikey")).toBeInTheDocument();
  });

  it("registers a first passkey: prompts for the device's TOTP code, drives navigator.credentials.create, and posts the result", async () => {
    vi.mocked(api.listWebAuthnCredentials).mockResolvedValue([]);
    vi.mocked(api.webauthnRegisterBegin).mockResolvedValue(sampleCreationOptions());
    vi.mocked(navigator.credentials.create).mockResolvedValue(fakeAttestationCredential());
    vi.mocked(api.webauthnRegisterFinish).mockResolvedValue({ ...activeCredential, id: "new-cred-id", label: "my-yubikey" });

    render(<TokensPage />);
    await screen.findByText("No passkeys enrolled yet.");

    await userEvent.type(screen.getByPlaceholderText("yubikey-5c"), "my-yubikey");
    await userEvent.click(screen.getByRole("button", { name: "Add passkey" }));

    expect(await screen.findByText("my-yubikey")).toBeInTheDocument();
    // The device's first passkey is always authorized by its TOTP code —
    // the factor the token got at mint time.
    expect(api.webauthnRegisterBegin).toHaveBeenCalledWith({ totpCode: "123456" });
    expect(api.webauthnRegisterFinish).toHaveBeenCalledWith(
      expect.objectContaining({ id: "new-cred-id", label: "my-yubikey" }),
    );
  });

  it("proves the existing passkey (no TOTP prompt) when one is already enrolled", async () => {
    vi.mocked(api.listWebAuthnCredentials).mockResolvedValue([activeCredential]);
    vi.mocked(api.webauthnAssertBegin).mockResolvedValue(sampleRequestOptions());
    vi.mocked(navigator.credentials.get).mockResolvedValue(fakeAssertionCredential());
    vi.mocked(api.webauthnRegisterBegin).mockResolvedValue(sampleCreationOptions());
    vi.mocked(navigator.credentials.create).mockResolvedValue(fakeAttestationCredential("second-cred-id"));
    vi.mocked(api.webauthnRegisterFinish).mockResolvedValue({ ...activeCredential, id: "second-cred-id", label: "second-key" });

    render(<TokensPage />);
    await screen.findByText("yubikey");

    await userEvent.type(screen.getByPlaceholderText("yubikey-5c"), "second-key");
    await userEvent.click(screen.getByRole("button", { name: "Add passkey" }));

    expect(await screen.findByText("second-key")).toBeInTheDocument();
    expect(api.webauthnAssertBegin).toHaveBeenCalledTimes(1);
    expect(navigator.credentials.get).toHaveBeenCalledTimes(1);
    // The one register/begin call carries the assertion, not a TOTP code —
    // and the operator never saw a prompt.
    expect(api.webauthnRegisterBegin).toHaveBeenCalledWith({ webauthnAssertion: expect.any(String) });
    expect(window.prompt).not.toHaveBeenCalled();
  });

  it("surfaces the server's refusal when the factor is rejected", async () => {
    vi.mocked(api.listWebAuthnCredentials).mockResolvedValue([]);
    vi.mocked(api.webauthnRegisterBegin).mockRejectedValue(new ApiError(401, "invalid or expired TOTP code"));

    render(<TokensPage />);
    await screen.findByText("No passkeys enrolled yet.");

    await userEvent.type(screen.getByPlaceholderText("yubikey-5c"), "my-key");
    await userEvent.click(screen.getByRole("button", { name: "Add passkey" }));

    expect(await screen.findByText("invalid or expired TOTP code")).toBeInTheDocument();
    expect(api.webauthnAssertBegin).not.toHaveBeenCalled();
  });

  it("aborts registration when the TOTP prompt is cancelled, without calling the server at all", async () => {
    vi.mocked(api.listWebAuthnCredentials).mockResolvedValue([]);
    vi.spyOn(window, "prompt").mockReturnValue(null);

    render(<TokensPage />);
    await screen.findByText("No passkeys enrolled yet.");

    await userEvent.type(screen.getByPlaceholderText("yubikey-5c"), "my-key");
    await userEvent.click(screen.getByRole("button", { name: "Add passkey" }));

    expect(api.webauthnRegisterBegin).not.toHaveBeenCalled();
  });

  it("refuses a blank TOTP code for a first passkey with a legible error, without calling the server", async () => {
    vi.mocked(api.listWebAuthnCredentials).mockResolvedValue([]);
    vi.spyOn(window, "prompt").mockReturnValue("   ");

    render(<TokensPage />);
    await screen.findByText("No passkeys enrolled yet.");

    await userEvent.type(screen.getByPlaceholderText("yubikey-5c"), "my-key");
    await userEvent.click(screen.getByRole("button", { name: "Add passkey" }));

    expect(await screen.findByText("A TOTP code is required to enroll this device's first passkey.")).toBeInTheDocument();
    expect(api.webauthnRegisterBegin).not.toHaveBeenCalled();
  });

  it("revokes a passkey after confirmation and reflects the revoked state", async () => {
    vi.mocked(api.listWebAuthnCredentials)
      .mockResolvedValueOnce([activeCredential])
      .mockResolvedValue([{ ...activeCredential, active: false, revoked_at: "2026-08-09T12:00:00Z" }]);
    vi.mocked(api.revokeWebAuthnCredential).mockResolvedValue(undefined);

    render(<TokensPage />);
    await screen.findByText("active");

    await userEvent.click(screen.getByRole("button", { name: "Revoke" }));

    expect(await screen.findByText("revoked")).toBeInTheDocument();
    expect(api.revokeWebAuthnCredential).toHaveBeenCalledWith("cred-1");
    expect(screen.queryByRole("button", { name: "Revoke" })).not.toBeInTheDocument();
  });

  it("does not revoke when the confirmation is declined", async () => {
    vi.mocked(api.listWebAuthnCredentials).mockResolvedValue([activeCredential]);
    vi.mocked(window.confirm).mockReturnValue(false);

    render(<TokensPage />);
    await screen.findByText("active");

    await userEvent.click(screen.getByRole("button", { name: "Revoke" }));

    expect(api.revokeWebAuthnCredential).not.toHaveBeenCalled();
    expect(screen.getByText("active")).toBeInTheDocument();
  });

  it("surfaces a friendly message when the authenticator ceremony is cancelled", async () => {
    vi.mocked(api.listWebAuthnCredentials).mockResolvedValue([]);
    vi.mocked(api.webauthnRegisterBegin).mockResolvedValue(sampleCreationOptions());
    vi.mocked(navigator.credentials.create).mockRejectedValue(new DOMException("cancelled", "NotAllowedError"));

    render(<TokensPage />);
    await screen.findByText("No passkeys enrolled yet.");

    await userEvent.type(screen.getByPlaceholderText("yubikey-5c"), "my-key");
    await userEvent.click(screen.getByRole("button", { name: "Add passkey" }));

    expect(await screen.findByText("Passkey ceremony was cancelled or timed out — try again.")).toBeInTheDocument();
  });
});
