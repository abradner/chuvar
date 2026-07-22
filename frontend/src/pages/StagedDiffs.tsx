import { useEffect, useState } from "react";
import { api, ApiError, type StagedDiff } from "../api/client";

const VERDICT_LABEL: Record<string, string> = {
  novel: "Novel",
  duplicate: "Duplicate",
  contradiction: "⚠ Contradiction — review carefully",
};

export function StagedDiffsPage() {
  const [diffs, setDiffs] = useState<StagedDiff[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [busyId, setBusyId] = useState<string | null>(null);

  const reload = () => {
    setLoading(true);
    api
      .listStagedDiffs("pending")
      .then(setDiffs)
      .catch((e: unknown) => setError(e instanceof ApiError ? e.message : String(e)))
      .finally(() => setLoading(false));
  };

  useEffect(reload, []);

  const decide = async (id: string, action: "approve" | "reject") => {
    setBusyId(id);
    setError(null);
    try {
      if (action === "approve") {
        await api.approveStagedDiff(id, "dashboard-reviewer");
      } else {
        await api.rejectStagedDiff(id, "dashboard-reviewer");
      }
      setDiffs((prev) => prev.filter((d) => d.id !== id));
    } catch (e) {
      setError(e instanceof ApiError ? e.message : String(e));
    } finally {
      setBusyId(null);
    }
  };

  if (loading) return <p>Loading…</p>;

  return (
    <section>
      <h2>Pending review</h2>
      {error && <p className="error">{error}</p>}
      {diffs.length === 0 && <p className="empty">Nothing waiting for review.</p>}
      <ul className="diff-list">
        {diffs.map((d) => (
          <li key={d.id} className="diff-card">
            <p className="diff-content">{d.content}</p>
            <p className="diff-meta">
              <span className="scopes">{d.proposed_scopes.join(", ")}</span>
              {d.dedupe_verdict && (
                <span className={`verdict verdict-${d.dedupe_verdict}`}>
                  {VERDICT_LABEL[d.dedupe_verdict] ?? d.dedupe_verdict}
                </span>
              )}
            </p>
            <div className="actions">
              <button disabled={busyId === d.id} onClick={() => decide(d.id, "approve")}>
                Approve
              </button>
              <button disabled={busyId === d.id} onClick={() => decide(d.id, "reject")} className="secondary">
                Reject
              </button>
            </div>
          </li>
        ))}
      </ul>
    </section>
  );
}
