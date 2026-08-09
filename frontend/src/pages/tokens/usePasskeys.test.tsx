// The hook layer's own guarantee, exercised without a view in front of it —
// same shape and reasoning as useTokens.test.tsx: proving the hook itself
// refuses a concurrent register(), not just relying on PasskeysView's
// disabled button (AGENTS.md §6, guard ceremonies live in the hook so any
// future caller inherits them).
import { act, renderHook } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { usePasskeys } from "./usePasskeys";
import { bufferToBase64url } from "./webauthnCodec";
import { api } from "../../api/client";
import type { CredentialCreationOptionsJSON, WebAuthnCredential } from "../../api/client";

vi.mock("../../api/client", async () => {
  const actual = await vi.importActual<typeof import("../../api/client")>("../../api/client");
  return {
    ...actual,
    api: {
      listWebAuthnCredentials: vi.fn(),
      webauthnRegisterBegin: vi.fn(),
      webauthnRegisterFinish: vi.fn(),
      webauthnAssertBegin: vi.fn(),
      revokeWebAuthnCredential: vi.fn(),
    },
  };
});

function creationOptions(): CredentialCreationOptionsJSON {
  return {
    publicKey: {
      rp: { id: "localhost", name: "Chuvar Test" },
      user: { id: bufferToBase64url(new Uint8Array([1]).buffer), name: "r", displayName: "r" },
      challenge: bufferToBase64url(new Uint8Array([9]).buffer),
      pubKeyCredParams: [{ type: "public-key", alg: -7 }],
    },
  };
}

const created: WebAuthnCredential = {
  id: "cred-1",
  label: "yubikey",
  active: true,
  attestation_type: "none",
  created_at: "2026-08-09T00:00:00Z",
};

function fakeAttestationCredential(): PublicKeyCredential {
  return {
    id: "cred-1",
    rawId: new Uint8Array([1]).buffer,
    type: "public-key",
    response: { clientDataJSON: new Uint8Array([1]).buffer, attestationObject: new Uint8Array([2]).buffer },
  } as unknown as PublicKeyCredential;
}

describe("usePasskeys", () => {
  beforeEach(() => {
    vi.resetAllMocks();
    vi.mocked(api.listWebAuthnCredentials).mockResolvedValue([]);
    // A first passkey is always authorized by the device's TOTP code — a
    // blank prompt would abort before reaching the in-flight guard under test.
    vi.spyOn(window, "prompt").mockReturnValue("123456");
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
  });

  it("reports not-supported when navigator.credentials lacks get(), even if create() exists", async () => {
    // Regression for the support check that only probed create(): this hook
    // also calls get() for assertions, so a browser exposing create() but not
    // get() must report unsupported up front rather than claiming support and
    // throwing at the first assertion.
    Object.defineProperty(navigator, "credentials", {
      value: { create: vi.fn() }, // no get()
      writable: true,
      configurable: true,
    });

    const { result } = renderHook(() => usePasskeys());
    await act(async () => {});

    expect(result.current.supported).toBe(false);
    // An unsupported browser has nothing to list — the fetch must be skipped.
    expect(api.listWebAuthnCredentials).not.toHaveBeenCalled();
  });

  it("refuses a second register() while one is already in flight, even called directly", async () => {
    let resolveBegin!: (o: CredentialCreationOptionsJSON) => void;
    vi.mocked(api.webauthnRegisterBegin).mockReturnValueOnce(new Promise((resolve) => (resolveBegin = resolve)));
    vi.mocked(navigator.credentials.create).mockResolvedValue(fakeAttestationCredential());
    vi.mocked(api.webauthnRegisterFinish).mockResolvedValue(created);

    const { result } = renderHook(() => usePasskeys());

    // Wait for the initial listWebAuthnCredentials fetch to settle so
    // `supported`/`credentials` are in their post-load state before this
    // test's own assertions.
    await act(async () => {});

    let firstCall!: Promise<boolean>;
    act(() => {
      firstCall = result.current.register("first-key");
    });
    expect(result.current.registering).toBe(true);

    let secondResult!: boolean;
    await act(async () => {
      secondResult = await result.current.register("second-key");
    });
    expect(secondResult).toBe(false);
    expect(result.current.error).toMatch(/already in flight/);

    await act(async () => {
      resolveBegin(creationOptions());
      await firstCall;
    });

    expect(api.webauthnRegisterBegin).toHaveBeenCalledTimes(1);
    expect(api.webauthnRegisterFinish).toHaveBeenCalledTimes(1);
  });
});
