import { afterEach, describe, expect, it, vi } from "vitest";
import { api, ApiError } from "./client";

function mockFetchOnce(response: Partial<Response>) {
  const fetchMock = vi.fn().mockResolvedValue({
    ok: true,
    status: 200,
    json: async () => ({}),
    ...response,
  } as Response);
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("api client", () => {
  it("parses a successful JSON response", async () => {
    mockFetchOnce({ ok: true, status: 200, json: async () => [{ id: "g1" }] });
    const result = await api.listGrants("agent-a");
    expect(result).toEqual([{ id: "g1" }]);
  });

  it("throws ApiError with the server's error message on a non-ok response", async () => {
    mockFetchOnce({ ok: false, status: 400, json: async () => ({ error: "subject is required" }) });
    await expect(api.listGrants("")).rejects.toMatchObject({ status: 400, message: "subject is required" });
  });

  it("falls back to statusText when the error body isn't JSON", async () => {
    mockFetchOnce({
      ok: false,
      status: 500,
      statusText: "Internal Server Error",
      json: async () => {
        throw new Error("not json");
      },
    });
    await expect(api.listGrants("agent-a")).rejects.toMatchObject({
      status: 500,
      message: "Internal Server Error",
    });
  });

  it("returns undefined for a 204 No Content response", async () => {
    mockFetchOnce({
      ok: true,
      status: 204,
      json: async () => {
        throw new Error("json() should not be called for a 204 response");
      },
    });
    const result = await api.revokeGrant("grant-1");
    expect(result).toBeUndefined();
  });

  it("thrown errors are instances of ApiError", async () => {
    mockFetchOnce({ ok: false, status: 404, json: async () => ({ error: "not found" }) });
    await expect(api.listGrants("agent-a")).rejects.toBeInstanceOf(ApiError);
  });

  it("sends the decided_by body on approveStagedDiff", async () => {
    const fetchMock = mockFetchOnce({ ok: true, status: 200, json: async () => ({}) });
    await api.approveStagedDiff("diff-1", "reviewer-a");

    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toContain("/api/staged-diffs/diff-1/approve");
    expect(JSON.parse(init.body as string)).toEqual({ decided_by: "reviewer-a" });
  });

  it("sends an Authorization bearer header on every request", async () => {
    const fetchMock = mockFetchOnce({ ok: true, status: 200, json: async () => [] });
    await api.listGrants("agent-a");

    const [, init] = fetchMock.mock.calls[0];
    const headers = init.headers as Record<string, string>;
    expect(headers.Authorization).toMatch(/^Bearer /);
  });
});
