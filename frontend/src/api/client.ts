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

export interface ReviewerToken {
  id: string;
  label: string;
  active: boolean;
  created_at: string;
  last_used_at?: string;
  revoked_at?: string;
}

export interface WebAuthnCredential {
  id: string;
  label: string;
  active: boolean;
  attestation_type: string;
  created_at: string;
  last_used_at?: string;
  clone_warning_at?: string;
  revoked_at?: string;
}

// The following mirror go-webauthn's protocol.CredentialCreation /
// protocol.CredentialAssertion JSON shapes exactly (field-for-field) — see
// backend/internal/api/webauthn.go's package comment. Consumed only by
// pages/tokens/webauthnCodec.ts, which converts them to/from the
// ArrayBuffer-based navigator.credentials Web API shapes; kept here rather
// than in that file because every other wire-format interface in this
// codebase lives in api/client.ts, and pages/ must not import from api/ in
// the other direction (AGENTS.md §6, "UI component standard" — View "Must
// not: Import from api/", generalized here to the whole pages/ tree owning
// no wire-format knowledge of its own).
interface WebAuthnCredentialDescriptor {
  type: "public-key";
  id: string;
  transports?: string[];
}

export interface CredentialCreationOptionsJSON {
  publicKey: {
    rp: { id: string; name: string };
    user: { id: string; name: string; displayName: string };
    challenge: string;
    pubKeyCredParams: { type: "public-key"; alg: number }[];
    timeout?: number;
    excludeCredentials?: WebAuthnCredentialDescriptor[];
    authenticatorSelection?: {
      authenticatorAttachment?: string;
      requireResidentKey?: boolean;
      residentKey?: string;
      userVerification?: string;
    };
    attestation?: string;
  };
}

export interface CredentialRequestOptionsJSON {
  publicKey: {
    challenge: string;
    timeout?: number;
    rpId?: string;
    allowCredentials?: WebAuthnCredentialDescriptor[];
    userVerification?: string;
  };
}

export interface CreatedReviewerToken extends ReviewerToken {
  // token and totp_enroll_uri are both returned exactly once, in this response
  // only — see backend/internal/api/tokens.go's createTokenResponse doc
  // comment. No API exposes either again afterward. Losing them means minting
  // a replacement from another still-enrolled device; if this was the only
  // one, the enrollment gate has already latched and recovery is direct
  // database access, not "start over."
  token: string;
  totp_enroll_uri: string;
}

// Page is the envelope the backend's cursor-paginated listing endpoints
// (GET /api/staged-diffs, GET /api/grants — see backend/internal/api/
// pagination.go) respond with. next_cursor is absent once no further page
// exists, not the empty string.
interface Page<T> {
  items: T[];
  next_cursor?: string;
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

// SecondFactor carries the device-local second factor (see
// backend/internal/api's requireStrongFactor) for mutations that grant or
// extend authority — TOTP and WebAuthn are equally-accepted alternatives
// (decided 2026-08-09, docs/decisions.md), never both required. Callers
// provide exactly one; every other request omits both headers entirely
// rather than sending them empty. Collected by pages/secondFactor.ts's
// promptSecondFactor (or the passkey hook's own ceremonies).
export interface SecondFactor {
  totpCode?: string;
  webauthnAssertion?: string;
}

async function request<T>(
  path: string,
  init?: RequestInit & { signal?: AbortSignal; totpCode?: string; webauthnAssertion?: string },
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
  if (init?.webauthnAssertion) {
    headers["X-Chuvar-WebAuthn-Assertion"] = init.webauthnAssertion;
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
  // The backend now paginates this listing (cursor-based, default page size
  // set server-side — see backend/internal/api/pagination.go) rather than
  // returning every matching row. This wrapper still resolves to a plain
  // array — unwrapping items here, rather than threading the envelope (and a
  // "load more"/cursor param) through StagedDiffsPage, keeps this change
  // minimal: at today's v0 scale the first page covers every real pending
  // queue, and surfacing pagination in the UI itself is a follow-up, not
  // this ticket's scope. A queue that grows past the server's default page
  // size will silently show only its first page here until that follow-up
  // lands.
  listStagedDiffs: (status = "pending", signal?: AbortSignal) =>
    request<Page<StagedDiff>>(`/api/staged-diffs?status=${encodeURIComponent(status)}`, { signal }).then(
      (p) => p.items,
    ),

  // approveStagedDiff/createGrant/approveGrantRequest/renewGrant require a
  // SecondFactor — the backend's requireStrongFactor gate rejects these
  // without a valid device-local second factor (see
  // backend/internal/api/api.go's Routes doc comment).
  approveStagedDiff: (id: string, factor: SecondFactor) =>
    request<unknown>(`/api/staged-diffs/${id}/approve`, { method: "POST", ...factor }),

  rejectStagedDiff: (id: string) => request<void>(`/api/staged-diffs/${id}/reject`, { method: "POST" }),

  // Same envelope-unwrapping as listStagedDiffs above, for the same reason —
  // see that wrapper's comment.
  listGrants: (subject: string, signal?: AbortSignal) =>
    request<Page<Grant>>(`/api/grants?subject=${encodeURIComponent(subject)}`, { signal }).then((p) => p.items),

  createGrant: (subject: string, scopes: string[], depth: string, factor: SecondFactor, ttlSeconds?: number) =>
    request<Grant>("/api/grants", {
      method: "POST",
      body: JSON.stringify({ subject, scopes, depth, ttl_seconds: ttlSeconds }),
      ...factor,
    }),

  revokeGrant: (id: string) => request<void>(`/api/grants/${id}/revoke`, { method: "POST" }),

  // renewGrant requires a SecondFactor (same gate as createGrant/
  // approveGrantRequest/approveStagedDiff) and ttlSeconds — unlike
  // createGrant's optional TTL, renewing into "no expiry" isn't allowed
  // (backend/internal/store's RenewGrant doc comment: it would defeat the
  // TTL-bounded security property renewal exists to preserve).
  renewGrant: (id: string, ttlSeconds: number, factor: SecondFactor) =>
    request<Grant>(`/api/grants/${id}/renew`, {
      method: "POST",
      body: JSON.stringify({ ttl_seconds: ttlSeconds }),
      ...factor,
    }),

  getFact: (id: string, signal?: AbortSignal) => request<Fact>(`/api/facts/${id}`, { signal }),

  listGrantRequests: (status = "pending", signal?: AbortSignal) =>
    request<GrantRequest[]>(`/api/grant-requests?status=${encodeURIComponent(status)}`, { signal }),

  approveGrantRequest: (id: string, factor: SecondFactor) =>
    request<Grant>(`/api/grant-requests/${id}/approve`, { method: "POST", ...factor }),

  denyGrantRequest: (id: string) => request<void>(`/api/grant-requests/${id}/deny`, { method: "POST" }),

  // Not a Page<T>: GET /api/tokens is deliberately unpaginated on the backend
  // (its handler writes a bare array — see listTokens in
  // backend/internal/api/tokens.go), unlike the staged-diff and grant
  // listings above. Stated because the two shapes now sit side by side in
  // this file and the bare array otherwise reads as an oversight — the
  // device list is operator-sized, so there is nothing to paginate. If the
  // backend ever wraps it, this must change with it.
  listTokens: (signal?: AbortSignal) => request<ReviewerToken[]>("/api/tokens", { signal }),

  // createToken's TOTP requirement is conditional server-side (backend's
  // createToken doc comment): required once any device has ever been
  // enrolled, not required for the very first (bootstrap) enrollment. totpCode
  // is therefore optional here rather than mandatory like createGrant/
  // approveGrantRequest/renewGrant — the caller passes what it has and the
  // server decides whether it was needed.
  createToken: (label: string, totpCode?: string) =>
    request<CreatedReviewerToken>("/api/tokens", { method: "POST", body: JSON.stringify({ label }), totpCode }),

  revokeToken: (id: string) => request<void>(`/api/tokens/${id}/revoke`, { method: "POST" }),

  // webauthnRegisterBegin always requires a factor the calling reviewer
  // token has already enrolled (requireExistingSecondFactor — see
  // backend/internal/api/webauthn.go's package comment): a TOTP code, or an
  // assertion of an existing passkey. Which one is the caller's choice, so
  // it takes the same SecondFactor shape as every other gated mutation.
  webauthnRegisterBegin: (factor: SecondFactor) =>
    request<CredentialCreationOptionsJSON>("/api/webauthn/register/begin", { method: "POST", ...factor }),

  // body is whatever webauthnCodec.encodeCreationResponse produced — no
  // factor header here (webauthnRegisterFinish is deliberately not re-gated;
  // see its own doc comment).
  webauthnRegisterFinish: (body: unknown) =>
    request<WebAuthnCredential>("/api/webauthn/register/finish", { method: "POST", body: JSON.stringify(body) }),

  webauthnAssertBegin: () => request<CredentialRequestOptionsJSON>("/api/webauthn/assert/begin", { method: "POST" }),

  listWebAuthnCredentials: (signal?: AbortSignal) => request<WebAuthnCredential[]>("/api/webauthn/credentials", { signal }),

  revokeWebAuthnCredential: (id: string) => request<void>(`/api/webauthn/credentials/${id}/revoke`, { method: "POST" }),
};

export { ApiError };
