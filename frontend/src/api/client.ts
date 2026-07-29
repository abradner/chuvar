// Thin typed wrapper over the Go REST API (backend/internal/api). No data-fetching
// library (React Query etc.) yet — plain fetch + useState/useEffect is enough at
// this scale, per AGENTS.md's "don't reach for it until the app needs it."

const BASE_URL = import.meta.env.VITE_API_BASE_URL ?? "http://localhost:8080";

// The backend requires a bearer token on every route — since the reviewer-tokens
// change (internal/api's package comment), this is a named, individually
// revocable device token, not a single shared secret across every browser that
// loads this page. Baking it into the frontend bundle via a Vite env var still
// means anyone who can load this page can read it out of the built JS —
// acceptable here for the same reason as before: the bundle is served from the
// same trust boundary (loopback, single operator) as the API itself, and this
// specific browser profile having its own token (rather than one secret shared
// by every device) is what makes it individually revocable without affecting
// anyone else's session. Not a pattern to reuse for anything serving untrusted
// users. Every request's decided_by/approved_by/revoked_by is now derived
// server-side from this token, never sent in the request body — see the removed
// reviewer-name field this replaced.
const AUTH_TOKEN = import.meta.env.VITE_API_AUTH_TOKEN ?? "";

// Every request gets a default timeout so a hung connection can't pin a component's
// busy state forever (e.g. an Approve button staying disabled with no way to
// recover short of a full page reload). Callers can still pass their own signal
// (e.g. to cancel a stale request when its inputs change) — see request() below.
const DEFAULT_TIMEOUT_MS = 10_000;

export interface StagedDiff {
  id: string;
  subject: string;
  content: string;
  proposed_scopes: string[];
  target_fact_id?: string;
  status: "pending" | "approved" | "rejected" | "committed";
  dedupe_verdict?: "novel" | "duplicate" | "contradiction";
  dedupe_candidate_fact_id?: string;
  created_at: string;
}

export interface Grant {
  id: string;
  subject: string;
  scopes: string[];
  depth: string;
  active: boolean;
  created_at: string;
  expires_at?: string;
  revoked_at?: string;
}

export interface Fact {
  id: string;
  content: string;
  scopes: string[];
  created_at: string;
  valid_at: string;
}

export interface GrantRequest {
  id: string;
  subject: string;
  requested_scopes: string[];
  depth: string;
  requested_ttl_seconds?: number;
  justification: string;
  status: "pending" | "approved" | "denied";
  created_at: string;
  decided_at?: string;
  decided_by?: string;
  resulting_grant_id?: string;
}

class ApiError extends Error {
  status: number;

  constructor(status: number, message: string) {
    super(message);
    this.status = status;
    this.name = "ApiError";
  }
}

// totpCode carries the device-local second factor (see backend/internal/api's
// requireTOTP) for mutations that grant or extend authority — every other
// request omits the header entirely rather than sending it empty.
async function request<T>(
  path: string,
  init?: RequestInit & { signal?: AbortSignal; totpCode?: string },
): Promise<T> {
  const timeoutSignal = AbortSignal.timeout(DEFAULT_TIMEOUT_MS);
  const signal = init?.signal ? AbortSignal.any([timeoutSignal, init.signal]) : timeoutSignal;

  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    Authorization: `Bearer ${AUTH_TOKEN}`,
  };
  if (init?.totpCode) {
    headers["X-Chuvar-TOTP-Code"] = init.totpCode;
  }

  const res = await fetch(`${BASE_URL}${path}`, {
    ...init,
    headers,
    signal,
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({ error: res.statusText }));
    throw new ApiError(res.status, body.error ?? res.statusText);
  }
  if (res.status === 204) {
    return undefined as T;
  }
  return res.json() as Promise<T>;
}

export const api = {
  listStagedDiffs: (status = "pending", signal?: AbortSignal) =>
    request<StagedDiff[]>(`/api/staged-diffs?status=${encodeURIComponent(status)}`, { signal }),

  // approveStagedDiff/createGrant/approveGrantRequest require totpCode — the
  // backend's requireTOTP gate rejects these without a valid device-local
  // second factor (see backend/internal/api/api.go's Routes doc comment).
  approveStagedDiff: (id: string, totpCode: string) =>
    request<unknown>(`/api/staged-diffs/${id}/approve`, { method: "POST", totpCode }),

  rejectStagedDiff: (id: string) => request<void>(`/api/staged-diffs/${id}/reject`, { method: "POST" }),

  listGrants: (subject: string, signal?: AbortSignal) =>
    request<Grant[]>(`/api/grants?subject=${encodeURIComponent(subject)}`, { signal }),

  createGrant: (subject: string, scopes: string[], depth: string, totpCode: string, ttlSeconds?: number) =>
    request<Grant>("/api/grants", {
      method: "POST",
      body: JSON.stringify({ subject, scopes, depth, ttl_seconds: ttlSeconds }),
      totpCode,
    }),

  revokeGrant: (id: string) => request<void>(`/api/grants/${id}/revoke`, { method: "POST" }),

  getFact: (id: string, signal?: AbortSignal) => request<Fact>(`/api/facts/${id}`, { signal }),

  listGrantRequests: (status = "pending", signal?: AbortSignal) =>
    request<GrantRequest[]>(`/api/grant-requests?status=${encodeURIComponent(status)}`, { signal }),

  approveGrantRequest: (id: string, totpCode: string) =>
    request<Grant>(`/api/grant-requests/${id}/approve`, { method: "POST", totpCode }),

  denyGrantRequest: (id: string) => request<void>(`/api/grant-requests/${id}/deny`, { method: "POST" }),
};

export { ApiError };
