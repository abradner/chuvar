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
    vi.clearAllMocks();
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
});
