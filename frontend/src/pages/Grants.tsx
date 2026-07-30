import { type FormEvent, useEffect, useState } from "react";
import { api, ApiError, type Grant, type GrantRequest } from "../api/client";

export function GrantsPage() {
  const [subject, setSubject] = useState("agent-a");
  const [grants, setGrants] = useState<Grant[]>([]);
  const [requests, setRequests] = useState<GrantRequest[]>([]);
  // Load errors and form/mutation errors are separate state on purpose: the list
  // effect re-runs on subject changes and refreshKey bumps, and a successful load
  // clearing a shared error would also erase an unrelated validation or
  // create/revoke error the operator is still reading (flagged by review on #13).
  // Each banner is cleared only by its own path. requestsLoadError is further
  // split out from loadError for the same reason, one level down: the grants
  // effect and the grant-requests effect both bump on refreshKey and run
  // independently, so a shared error here had the identical bug reintroduced —
  // a grant-requests fetch failing, then a grants fetch succeeding a moment
  // later, would silently clear the request-list failure the operator hadn't
  // even seen yet. Found in review (reported independently by two reviewers).
  const [loadError, setLoadError] = useState<string | null>(null);
  const [requestsLoadError, setRequestsLoadError] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);

  const [newScopes, setNewScopes] = useState("");
  const [newDepth, setNewDepth] = useState("facts");
  const [newTTLMinutes, setNewTTLMinutes] = useState("");

  // refreshKey exists so create/revoke can trigger a reload through the exact
  // same cancellable effect the subject field uses, instead of firing a separate,
  // uncancelled fetch. The old separate reload() captured `subject` from the
  // render that started the mutation — if the operator changed subjects while a
  // revoke/create was in flight, that stale closure could resolve after the
  // subject-change effect and overwrite the new subject's list with the old
  // one's. Bumping refreshKey re-runs this effect with the *current* subject,
  // and its own AbortController still supersedes any request that's now stale.
  const [refreshKey, setRefreshKey] = useState(0);
  useEffect(() => {
    const controller = new AbortController();
    api
      .listGrants(subject.trim(), controller.signal)
      .then((g) => {
        setGrants(g);
        // A successful load clears any stale banner from an earlier failed load —
        // and only that banner; form/mutation errors live in `error` and survive.
        setLoadError(null);
      })
      .catch((e: unknown) => {
        if (e instanceof DOMException && e.name === "AbortError") return;
        setLoadError(e instanceof ApiError ? e.message : String(e));
      });
    return () => controller.abort();
  }, [subject, refreshKey]);

  // Pending grant requests are shown across all subjects, not just the one typed
  // into the Subject field above — a request is exactly the thing that tells the
  // operator a new subject exists and wants access, so filtering it by the
  // subject field would hide the requests most worth seeing.
  useEffect(() => {
    const controller = new AbortController();
    api
      .listGrantRequests("pending", controller.signal)
      .then((r) => {
        setRequests(r);
        setRequestsLoadError(null);
      })
      .catch((e: unknown) => {
        if (e instanceof DOMException && e.name === "AbortError") return;
        setRequestsLoadError(e instanceof ApiError ? e.message : String(e));
      });
    return () => controller.abort();
  }, [refreshKey]);

  const decideRequest = async (id: string, action: "approve" | "deny") => {
    // Approving requires the device-local TOTP second factor (requireTOTP,
    // backend/internal/api/api.go) — deny doesn't, since it only reduces
    // authority, not the self-escalation vector the gate exists for. A plain
    // prompt() is a deliberately minimal stopgap UI, not the eventual WebAuthn
    // surface.
    let totpCode = "";
    if (action === "approve") {
      totpCode = window.prompt("Enter TOTP code to approve") ?? "";
      if (!totpCode) return;
    }
    setBusyId(id);
    setError(null);
    try {
      if (action === "approve") {
        await api.approveGrantRequest(id, totpCode);
      } else {
        await api.denyGrantRequest(id);
      }
      setRequests((prev) => prev.filter((r) => r.id !== id));
      // An approval creates a real grant, which may belong to the subject
      // currently shown below — refresh that list too.
      setRefreshKey((k) => k + 1);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : String(e));
    } finally {
      setBusyId(null);
    }
  };

  const revoke = async (id: string) => {
    setBusyId(id);
    setError(null);
    try {
      await api.revokeGrant(id);
      setRefreshKey((k) => k + 1);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : String(e));
    } finally {
      setBusyId(null);
    }
  };

  // renewGrant requires a TTL, unlike createGrant's optional one (the backend
  // rejects a missing/non-positive ttl_seconds — see api/client.ts's comment),
  // so this prompts for minutes the same way createGrant's form field does,
  // then TOTP the same way decideRequest's approve path does. Two sequential
  // window.prompt()s, same deliberately-minimal stopgap UI as the rest of this
  // page — not the eventual WebAuthn surface.
  const renew = async (id: string) => {
    const minutesInput = window.prompt("Renew for how many minutes?");
    if (!minutesInput) return;
    const minutes = Number(minutesInput);
    if (!Number.isInteger(minutes) || minutes <= 0) {
      setError("TTL must be a positive whole number of minutes");
      return;
    }
    const totpCode = window.prompt("Enter TOTP code to renew") ?? "";
    if (!totpCode) return;

    setBusyId(id);
    setError(null);
    try {
      await api.renewGrant(id, minutes * 60, totpCode);
      setRefreshKey((k) => k + 1);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : String(e));
    } finally {
      setBusyId(null);
    }
  };

  // Mirrors the backend's grantExpiryWarningWindow (internal/api/events.go) —
  // no shared source of truth between the two, so this is a best-effort visual
  // hint kept conceptually in sync by convention, not a value either side reads
  // from the other. Purely cosmetic (a "renew soon" nudge); the backend's own
  // SSE grant_expiring event is what pushbridge/approver actually act on, and
  // this page doesn't consume SSE at all (events.go's own doc comment on why:
  // EventSource can't set an Authorization header without a polyfill).
  const expiringWarningWindowMs = 24 * 60 * 60 * 1000;
  const isExpiringSoon = (g: Grant) =>
    g.active && g.expires_at != null && new Date(g.expires_at).getTime() - Date.now() <= expiringWarningWindowMs;

  const createGrant = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);

    const scopes = newScopes
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);
    if (scopes.length === 0) {
      setError("At least one scope is required");
      return;
    }

    // A non-numeric or blank TTL must not silently become "no expiry" — this
    // product's whole premise is time-boxed access, so a typo here creating a
    // permanent grant with no error shown would be exactly the wrong failure
    // mode. Number("") is 0 and Number("abc") is NaN; both need to be rejected
    // explicitly rather than falling through to `undefined` (no expiry).
    // Number.isInteger (not isFinite) also rejects decimal minutes — the backend's
    // ttl_seconds is an integer, and something like "0.1" minutes * 60 can land on
    // a non-integer number of seconds (floating-point rounding) that fails the
    // backend's JSON decode instead of surfacing a clear validation message here.
    let ttlSeconds: number | undefined;
    if (newTTLMinutes.trim() !== "") {
      const minutes = Number(newTTLMinutes);
      if (!Number.isInteger(minutes) || minutes <= 0) {
        setError("TTL must be a positive whole number of minutes, or left blank for no expiry");
        return;
      }
      ttlSeconds = minutes * 60;
    }

    // createGrant is a direct capability grant — the same requireTOTP gate as
    // approving a grant request (it's the other REST path that ever creates a
    // real grant; see the backend's Routes doc comment).
    const totpCode = window.prompt("Enter TOTP code to create this grant") ?? "";
    if (!totpCode) return;

    setCreating(true);
    try {
      await api.createGrant(subject.trim(), scopes, newDepth, totpCode, ttlSeconds);
      setNewScopes("");
      setRefreshKey((k) => k + 1);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : String(e));
    } finally {
      setCreating(false);
    }
  };

  return (
    <section>
      <h2>Grants</h2>
      {loadError && <p className="error">{loadError}</p>}
      {requestsLoadError && <p className="error">{requestsLoadError}</p>}
      {error && <p className="error">{error}</p>}

      {requests.length > 0 && (
        <>
          <h3>Requested by agents</h3>
          <ul className="grant-request-list">
            {requests.map((r) => (
              <li key={r.id} className="grant-card">
                <p className="diff-meta">
                  <span className="proposer">from {r.subject}</span>
                </p>
                <p className="scopes">{r.requested_scopes.join(", ")}</p>
                <p className="grant-meta">
                  depth: {r.depth}
                  {r.requested_ttl_seconds != null && ` · ${Math.round(r.requested_ttl_seconds / 60)} min`}
                </p>
                {r.justification && <p className="diff-content">{r.justification}</p>}
                <div className="actions">
                  <button disabled={busyId === r.id} onClick={() => decideRequest(r.id, "approve")}>
                    Approve
                  </button>
                  <button disabled={busyId === r.id} onClick={() => decideRequest(r.id, "deny")} className="secondary">
                    Deny
                  </button>
                </div>
              </li>
            ))}
          </ul>
        </>
      )}

      <label className="subject-field">
        Subject
        <input value={subject} onChange={(e) => setSubject(e.target.value)} placeholder="agent-a" />
      </label>

      <ul className="grant-list">
        {grants.map((g) => (
          <li key={g.id} className="grant-card">
            <p className="scopes">{g.scopes.join(", ")}</p>
            <p className="grant-meta">
              depth: {g.depth} · {g.active ? "active" : g.revoked_at ? "revoked" : "expired"}
              {g.expires_at && ` · expires ${new Date(g.expires_at).toLocaleString()}`}
              {isExpiringSoon(g) && <span className="expiring-soon"> · expiring soon</span>}
            </p>
            {g.active && (
              <div className="actions">
                <button disabled={busyId === g.id} onClick={() => renew(g.id)}>
                  Renew
                </button>
                <button disabled={busyId === g.id} onClick={() => revoke(g.id)} className="secondary">
                  Revoke
                </button>
              </div>
            )}
          </li>
        ))}
        {grants.length === 0 && <p className="empty">No grants for this subject.</p>}
      </ul>

      <form onSubmit={createGrant} className="new-grant-form">
        <h3>New grant</h3>
        <label>
          Scopes (comma-separated)
          <input
            value={newScopes}
            onChange={(e) => setNewScopes(e.target.value)}
            placeholder="identity.basic, projects.spritz.read"
          />
        </label>
        <label>
          Depth
          <select value={newDepth} onChange={(e) => setNewDepth(e.target.value)}>
            <option value="summary">summary</option>
            <option value="facts">facts</option>
            <option value="full">full</option>
          </select>
        </label>
        <label>
          TTL (minutes, blank = no expiry)
          {/* type="text" rather than type="number" is deliberate: a native number
              input silently blocks form submission on an out-of-range/invalid
              value (varies by browser) before our own onSubmit handler ever runs,
              so the clearer, consistently-styled validation message below never
              gets a chance to show. inputMode still gives mobile keyboards the
              numeric layout; our own JS validation is the single source of truth
              for what counts as valid. */}
          <input
            type="text"
            inputMode="numeric"
            value={newTTLMinutes}
            onChange={(e) => setNewTTLMinutes(e.target.value)}
          />
        </label>
        <button type="submit" disabled={creating}>
          Create grant
        </button>
      </form>
    </section>
  );
}
