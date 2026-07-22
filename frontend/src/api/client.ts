// Thin typed wrapper over the Go REST API (backend/internal/api). No data-fetching
// library (React Query etc.) yet — plain fetch + useState/useEffect is enough at
// this scale, per AGENTS.md's "don't reach for it until the app needs it."

const BASE_URL = import.meta.env.VITE_API_BASE_URL ?? "http://localhost:8080";

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

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE_URL}${path}`, {
    headers: { "Content-Type": "application/json" },
    ...init,
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
  listStagedDiffs: (status = "pending") =>
    request<StagedDiff[]>(`/api/staged-diffs?status=${encodeURIComponent(status)}`),

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

  listGrants: (subject: string) => request<Grant[]>(`/api/grants?subject=${encodeURIComponent(subject)}`),

  createGrant: (subject: string, scopes: string[], depth: string, ttlSeconds?: number) =>
    request<Grant>("/api/grants", {
      method: "POST",
      body: JSON.stringify({ subject, scopes, depth, ttl_seconds: ttlSeconds }),
    }),

  revokeGrant: (id: string) =>
    request<void>(`/api/grants/${id}/revoke`, { method: "POST" }),
};

export { ApiError };
