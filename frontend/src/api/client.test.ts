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
    // listGrants unwraps the backend's { items, next_cursor } pagination
    // envelope back into a plain array — see client.ts's own comment on why.
    mockFetchOnce({ ok: true, status: 200, json: async () => ({ items: [{ id: "g1" }] }) });
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

  it("sends no body on approveStagedDiff — decided_by is derived server-side from the auth token", async () => {
    const fetchMock = mockFetchOnce({ ok: true, status: 200, json: async () => ({}) });
    await api.approveStagedDiff("diff-1", "123456");

    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toContain("/api/staged-diffs/diff-1/approve");
    expect(init.body).toBeUndefined();
  });

  it("sends the TOTP code as a header on approveStagedDiff, not the request body", async () => {
    const fetchMock = mockFetchOnce({ ok: true, status: 200, json: async () => ({}) });
    await api.approveStagedDiff("diff-1", "123456");

    const [, init] = fetchMock.mock.calls[0];
    const headers = init.headers as Record<string, string>;
    expect(headers["X-Chuvar-TOTP-Code"]).toBe("123456");
  });

  it("omits the TOTP header entirely on requests that don't need it", async () => {
    const fetchMock = mockFetchOnce({ ok: true, status: 200, json: async () => ({ items: [] }) });
    await api.listGrants("agent-a");

    const [, init] = fetchMock.mock.calls[0];
    const headers = init.headers as Record<string, string>;
    expect(headers["X-Chuvar-TOTP-Code"]).toBeUndefined();
  });

  it("sends no body on revokeGrant — revoked_by is derived server-side from the auth token", async () => {
    const fetchMock = mockFetchOnce({ ok: true, status: 204 });
    await api.revokeGrant("grant-1");

    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toContain("/api/grants/grant-1/revoke");
    expect(init.body).toBeUndefined();
  });

  it("sends the grant fields on createGrant, with no approved_by — derived server-side from the auth token", async () => {
    const fetchMock = mockFetchOnce({ ok: true, status: 201, json: async () => ({}) });
    await api.createGrant("agent-a", ["identity.basic"], "facts", "123456", 300);

    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toContain("/api/grants");
    expect(JSON.parse(init.body as string)).toEqual({
      subject: "agent-a",
      scopes: ["identity.basic"],
      depth: "facts",
      ttl_seconds: 300,
    });
  });

  it("sends an Authorization bearer header on every request", async () => {
    const fetchMock = mockFetchOnce({ ok: true, status: 200, json: async () => ({ items: [] }) });
    await api.listGrants("agent-a");

    const [, init] = fetchMock.mock.calls[0];
    const headers = init.headers as Record<string, string>;
    expect(headers.Authorization).toMatch(/^Bearer /);
  });
});
