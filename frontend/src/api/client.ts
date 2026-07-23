// Thin typed wrapper over the Go REST API (backend/internal/api). No data-fetching
// library (React Query etc.) yet — plain fetch + useState/useEffect is enough at
// this scale, per AGENTS.md's "don't reach for it until the app needs it."

const BASE_URL = import.meta.env.VITE_API_BASE_URL ?? "http://localhost:8080";

// The backend now requires a bearer token on every route (see internal/api's
// package comment — a deliberately minimal v0 auth answer, one shared secret, not
// real per-user identity). Baking it into the frontend bundle via a Vite env var
// means anyone who can load this page can read it out of the built JS — acceptable
// here because the whole point of the token is "prove you're the one trusted local
// operator," and the bundle is served from the same trust boundary (loopback,
// single operator) as the API itself. This is not a pattern to reuse for anything
// serving untrusted users.
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

class ApiError extends Error {
  status: number;

  constructor(status: number, message: string) {
    super(message);
    this.status = status;
    this.name = "ApiError";
  }
}

async function request<T>(path: string, init?: RequestInit & { signal?: AbortSignal }): Promise<T> {
  const timeoutSignal = AbortSignal.timeout(DEFAULT_TIMEOUT_MS);
  const signal = init?.signal ? AbortSignal.any([timeoutSignal, init.signal]) : timeoutSignal;

  const res = await fetch(`${BASE_URL}${path}`, {
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${AUTH_TOKEN}`,
    },
    ...init,
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

  approveStagedDiff: (id: string, decidedBy: string) =>
    request<unknown>(`/api/staged-diffs/${id}/approve`, {
      method: "POST",
      body: JSON.stringify({ decided_by: decidedBy }),
    }),

  rejectStagedDiff: (id: string, decidedBy: string) =>
    request<void>(`/api/staged-diffs/${id}/reject`, {
      method: "POST",
      body: JSON.stringify({ decided_by: decidedBy }),
    }),

  listGrants: (subject: string, signal?: AbortSignal) =>
    request<Grant[]>(`/api/grants?subject=${encodeURIComponent(subject)}`, { signal }),

  createGrant: (subject: string, scopes: string[], depth: string, ttlSeconds?: number) =>
    request<Grant>("/api/grants", {
      method: "POST",
      body: JSON.stringify({ subject, scopes, depth, ttl_seconds: ttlSeconds }),
    }),

  revokeGrant: (id: string) =>
    request<void>(`/api/grants/${id}/revoke`, { method: "POST" }),
};

export { ApiError };
