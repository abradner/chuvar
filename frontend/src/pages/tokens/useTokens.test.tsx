// The hook layer's own guarantees, exercised without a view in front of it.
// Tokens.test.tsx and TokensView.test.tsx cover behavior reachable through
// TokensView; this file exists only for the one case that requires bypassing
// it — proving the hook enforces its own invariant rather than relying on the
// view's disabled button, which is UX, not the chokepoint (AGENTS.md §6:
// guard ceremonies live in the hook so any future caller inherits them).
import { act, renderHook } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { useTokens } from "./useTokens";
import { api } from "../../api/client";
import type { CreatedReviewerToken } from "../../api/client";

vi.mock("../../api/client", async () => {
  const actual = await vi.importActual<typeof import("../../api/client")>("../../api/client");
  return {
    ...actual,
    api: {
      listTokens: vi.fn(),
      createToken: vi.fn(),
      revokeToken: vi.fn(),
    },
  };
});

const first: CreatedReviewerToken = {
  id: "token-1",
  label: "alex-phone",
  active: true,
  created_at: "2026-08-07T00:00:00Z",
  token: "first-token",
  totp_enroll_uri: "otpauth://totp/Chuvar:alex-phone?secret=JBSWY3DPEHPK3PXP&issuer=Chuvar",
};

const second: CreatedReviewerToken = {
  ...first,
  id: "token-2",
  label: "alex-laptop",
  token: "second-token",
};

describe("useTokens", () => {
  beforeEach(() => {
    // resetAllMocks, not clearAllMocks: a test whose guard refuses a second
    // create leaves an unconsumed queued mockResolvedValueOnce/mockReturnValueOnce
    // behind, which clearAllMocks does not drop — it would otherwise leak into
    // the next test's first createToken call.
    vi.resetAllMocks();
    vi.mocked(api.listTokens).mockResolvedValue([]);
    vi.spyOn(window, "prompt").mockReturnValue("");
  });

  it("refuses to overwrite a pending reveal, even called directly", async () => {
    vi.mocked(api.createToken).mockResolvedValueOnce(first).mockResolvedValueOnce(second);

    const { result } = renderHook(() => useTokens());

    await act(async () => {
      await result.current.create("alex-phone");
    });
    expect(result.current.justCreated?.token).toBe("first-token");

    await act(async () => {
      await result.current.create("alex-laptop");
    });

    expect(result.current.justCreated?.token).toBe("first-token");
    expect(api.createToken).toHaveBeenCalledTimes(1);
    expect(result.current.error).toMatch(/already pending/);
  });

  it("refuses a second create while one is already in flight, even called directly", async () => {
    // The disabled button covers this in the UI, but a second caller of the
    // hook itself — not gated by that button — could otherwise fire a
    // concurrent request before justCreated is even set. Found in review
    // (Copilot).
    let resolveCreate!: (token: CreatedReviewerToken) => void;
    vi.mocked(api.createToken).mockReturnValueOnce(new Promise((resolve) => (resolveCreate = resolve)));

    const { result } = renderHook(() => useTokens());

    // An async act callback, not a plain sync one: create's guard now sits
    // behind `await promptSecondFactor(...)` (the optional TOTP-or-passkey
    // ceremony), and an async function always yields at least one microtask
    // even along a path with no real await inside it — a sync act callback
    // returned before setCreating(true) ran. Awaiting act lets that
    // microtask (and the setCreating(true) state update it gates) settle
    // before the assertion below, which is what lets the second call
    // observe creating=true through a fresh closure.
    let firstCall!: Promise<boolean>;
    await act(async () => {
      firstCall = result.current.create("alex-phone");
    });
    expect(result.current.creating).toBe(true);

    const secondResult = await result.current.create("alex-laptop");
    expect(secondResult).toBe(false);

    await act(async () => {
      resolveCreate(first);
      await firstCall;
    });

    expect(result.current.justCreated?.token).toBe("first-token");
    expect(api.createToken).toHaveBeenCalledTimes(1);
  });
});
