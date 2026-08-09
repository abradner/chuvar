// Direct unit coverage of promptSecondFactor's optional mode
// (PromptSecondFactorOptions) — the two "this device genuinely has nothing
// to prove" degrade branches useTokens.create relies on, plus a pin that the
// default (mandatory) behavior every other caller (Grants, StagedDiffs)
// depends on is unchanged by adding that mode. Behaviour reachable only
// through a full page (the real navigator.credentials.get() ceremony
// end-to-end) is covered at that level in Tokens.test.tsx/StagedDiffs.test.tsx;
// this file exists for the branches inside promptSecondFactor itself.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { promptSecondFactor } from "./secondFactor";
import { api, ApiError } from "../api/client";

vi.mock("../api/client", async () => {
  const actual = await vi.importActual<typeof import("../api/client")>("../api/client");
  return {
    ...actual,
    api: {
      webauthnAssertBegin: vi.fn(),
    },
  };
});

function stubPasskeySupport(getImpl: () => Promise<PublicKeyCredential | null>) {
  Object.defineProperty(window, "PublicKeyCredential", {
    value: function PublicKeyCredential() {},
    writable: true,
    configurable: true,
  });
  Object.defineProperty(navigator, "credentials", {
    value: { get: vi.fn(getImpl) },
    writable: true,
    configurable: true,
  });
}

function clearPasskeySupport() {
  Reflect.deleteProperty(window, "PublicKeyCredential");
  Reflect.deleteProperty(navigator, "credentials");
}

describe("promptSecondFactor", () => {
  beforeEach(() => {
    vi.resetAllMocks();
  });

  afterEach(() => {
    clearPasskeySupport();
    vi.restoreAllMocks();
  });

  it("returns an empty factor for an optional caller when blank and the browser has no passkey support", async () => {
    vi.spyOn(window, "prompt").mockReturnValue("");

    const factor = await promptSecondFactor("mint a new device token", { optional: true });

    expect(factor).toEqual({});
    expect(api.webauthnAssertBegin).not.toHaveBeenCalled();
  });

  it("still requires a TOTP code when blank, no passkey support, and the caller did not opt in to optional", async () => {
    vi.spyOn(window, "prompt").mockReturnValue("");

    await expect(promptSecondFactor("approve")).rejects.toThrow(/TOTP code is required/);
  });

  it("returns an empty factor for an optional caller when the calling token has no passkey enrolled (409)", async () => {
    // webauthnAssertBegin scopes to the calling reviewer token's own
    // credentials and answers 409 when it has none (backend's own doc
    // comment) — the "nothing to prove" signal an optional caller degrades
    // on, distinct from every other ApiError status.
    vi.spyOn(window, "prompt").mockReturnValue("");
    stubPasskeySupport(() => Promise.resolve(null));
    vi.mocked(api.webauthnAssertBegin).mockRejectedValue(new ApiError(409, "no passkey enrolled for this reviewer token"));

    const factor = await promptSecondFactor("mint a new device token", { optional: true });

    expect(factor).toEqual({});
  });

  it("propagates a non-409 ApiError from webauthnAssertBegin even for an optional caller", async () => {
    // Only "no passkey enrolled" (409) is a legitimate "nothing to prove"
    // signal — an auth failure or server error must still surface as an
    // error, not silently degrade to no factor.
    vi.spyOn(window, "prompt").mockReturnValue("");
    stubPasskeySupport(() => Promise.resolve(null));
    vi.mocked(api.webauthnAssertBegin).mockRejectedValue(new ApiError(401, "unauthorized"));

    await expect(promptSecondFactor("mint a new device token", { optional: true })).rejects.toThrow("unauthorized");
  });

  it("collects a real passkey assertion for an optional caller when the calling token has one enrolled", async () => {
    // The actual hole this exists to close: a reviewer whose only surviving
    // factor is a passkey (no working TOTP) must still be able to satisfy
    // an optional-factor gate, not just a mandatory one.
    vi.spyOn(window, "prompt").mockReturnValue("");
    stubPasskeySupport(() =>
      Promise.resolve({
        id: "cred-1",
        rawId: new Uint8Array([1]).buffer,
        type: "public-key",
        response: {
          clientDataJSON: new Uint8Array([2]).buffer,
          authenticatorData: new Uint8Array([3]).buffer,
          signature: new Uint8Array([4]).buffer,
        },
      } as unknown as PublicKeyCredential),
    );
    vi.mocked(api.webauthnAssertBegin).mockResolvedValue({ publicKey: { challenge: "AAAA" } });

    const factor = await promptSecondFactor("mint a new device token", { optional: true });

    expect(factor).toEqual({ webauthnAssertion: expect.any(String) });
  });
});
