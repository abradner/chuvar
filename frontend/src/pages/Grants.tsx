import { type FormEvent, useEffect, useState } from "react";
import { api, ApiError, type Grant } from "../api/client";

export function GrantsPage() {
  const [subject, setSubject] = useState("agent-a");
  const [grants, setGrants] = useState<Grant[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [busyId, setBusyId] = useState<string | null>(null);

  const [newScopes, setNewScopes] = useState("");
  const [newDepth, setNewDepth] = useState("facts");
  const [newTTLMinutes, setNewTTLMinutes] = useState("");

  const reload = (forSubject: string) => {
    api
      .listGrants(forSubject)
      .then(setGrants)
      .catch((e: unknown) => setError(e instanceof ApiError ? e.message : String(e)));
  };

  useEffect(() => reload(subject), [subject]);

  const revoke = async (id: string) => {
    setBusyId(id);
    setError(null);
    try {
      await api.revokeGrant(id);
      reload(subject);
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
    try {
      await api.createGrant(
        subject,
        scopes,
        newDepth,
        newTTLMinutes ? Number(newTTLMinutes) * 60 : undefined,
      );
      setNewScopes("");
      reload(subject);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : String(e));
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
          <input
            type="number"
            min="1"
            value={newTTLMinutes}
            onChange={(e) => setNewTTLMinutes(e.target.value)}
          />
        </label>
        <button type="submit">Create grant</button>
      </form>
    </section>
  );
}
