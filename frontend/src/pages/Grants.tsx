import { type FormEvent, useEffect, useState } from "react";
import { api, ApiError, type Grant } from "../api/client";

export function GrantsPage() {
  const [subject, setSubject] = useState("agent-a");
  const [grants, setGrants] = useState<Grant[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);

  const [newScopes, setNewScopes] = useState("");
  const [newDepth, setNewDepth] = useState("facts");
  const [newTTLMinutes, setNewTTLMinutes] = useState("");

  // Typing in the subject field fires a fetch per keystroke with nothing to
  // guarantee responses resolve in request order — without cancelling the
  // previous in-flight request, a slow response for an earlier value (e.g. "a")
  // could resolve after a faster one for the current value ("agent-a") and
  // silently overwrite the list with the wrong subject's grants. An
  // AbortController per effect run, cancelled on the next run/unmount, fixes
  // that: a superseded request never gets to call setGrants.
  useEffect(() => {
    const controller = new AbortController();
    api
      .listGrants(subject.trim(), controller.signal)
      .then(setGrants)
      .catch((e: unknown) => {
        if (e instanceof DOMException && e.name === "AbortError") return;
        setError(e instanceof ApiError ? e.message : String(e));
      });
    return () => controller.abort();
  }, [subject]);

  const reload = () => {
    api
      .listGrants(subject.trim())
      .then(setGrants)
      .catch((e: unknown) => setError(e instanceof ApiError ? e.message : String(e)));
  };

  const revoke = async (id: string) => {
    setBusyId(id);
    setError(null);
    try {
      await api.revokeGrant(id);
      reload();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : String(e));
    } finally {
      setBusyId(null);
    }
  };

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

    setCreating(true);
    try {
      await api.createGrant(subject.trim(), scopes, newDepth, ttlSeconds);
      setNewScopes("");
      reload();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : String(e));
    } finally {
      setCreating(false);
    }
  };

  return (
    <section>
      <h2>Grants</h2>
      <label className="subject-field">
        Subject
        <input value={subject} onChange={(e) => setSubject(e.target.value)} placeholder="agent-a" />
      </label>

      {error && <p className="error">{error}</p>}

      <ul className="grant-list">
        {grants.map((g) => (
          <li key={g.id} className="grant-card">
            <p className="scopes">{g.scopes.join(", ")}</p>
            <p className="grant-meta">
              depth: {g.depth} · {g.active ? "active" : g.revoked_at ? "revoked" : "expired"}
              {g.expires_at && ` · expires ${new Date(g.expires_at).toLocaleString()}`}
            </p>
            {g.active && (
              <button disabled={busyId === g.id} onClick={() => revoke(g.id)} className="secondary">
                Revoke
              </button>
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
