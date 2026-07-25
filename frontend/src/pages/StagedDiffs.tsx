import { useEffect, useState } from "react";
import { api, ApiError, type Fact, type StagedDiff } from "../api/client";

const VERDICT_LABEL: Record<string, string> = {
  novel: "Novel",
  duplicate: "Duplicate",
  contradiction: "⚠ Contradiction — review carefully",
};

type TargetFactState = { status: "loading" } | { status: "loaded"; fact: Fact } | { status: "error"; message: string };

export function StagedDiffsPage() {
  const [diffs, setDiffs] = useState<StagedDiff[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [busyId, setBusyId] = useState<string | null>(null);
  // Keyed by target_fact_id, not diff id — several diffs could (in principle)
  // target the same fact, and there's no reason to fetch it twice.
  const [targetFacts, setTargetFacts] = useState<Record<string, TargetFactState>>({});

  const reload = () => {
    setLoading(true);
    api
      .listStagedDiffs("pending")
      .then((d) => {
        setDiffs(d);
        // A successful reload clears any error banner left over from an earlier
        // failed load — otherwise a stale error sits above a perfectly good list.
        setError(null);
      })
      .catch((e: unknown) => setError(e instanceof ApiError ? e.message : String(e)))
      .finally(() => setLoading(false));
  };

  useEffect(reload, []);

  // Fetch the current content of every target_fact_id this batch of diffs
  // references, so a reviewer sees what Approve would actually replace instead of
  // an opaque UUID — a diff with a target is a supersession, not just a new fact,
  // and that wasn't visible anywhere in this UI before. Only fetches IDs not
  // already in targetFacts, so this doesn't re-fetch on every unrelated re-render.
  useEffect(() => {
    const missing = [...new Set(diffs.map((d) => d.target_fact_id).filter((id): id is string => !!id))].filter(
      (id) => !(id in targetFacts),
    );
    if (missing.length === 0) return;

    setTargetFacts((prev) => {
      const next = { ...prev };
      for (const id of missing) next[id] = { status: "loading" };
      return next;
    });

    for (const id of missing) {
      api
        .getFact(id)
        .then((fact) => setTargetFacts((prev) => ({ ...prev, [id]: { status: "loaded", fact } })))
        .catch((e: unknown) =>
          setTargetFacts((prev) => ({
            ...prev,
            [id]: { status: "error", message: e instanceof ApiError ? e.message : String(e) },
          })),
        );
    }
    // targetFacts is intentionally excluded: it's this effect's own output, and
    // including it would re-run the effect every time a fetch resolves.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [diffs]);

  const decide = async (id: string, action: "approve" | "reject") => {
    setBusyId(id);
    setError(null);
    try {
      if (action === "approve") {
        await api.approveStagedDiff(id);
      } else {
        await api.rejectStagedDiff(id);
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
        {diffs.map((d) => {
          const target = d.target_fact_id ? targetFacts[d.target_fact_id] : undefined;
          // Approval is blocked until a target fact (if any) has actually been
          // fetched and confirmed — approving blind on an unresolved or failed
          // target lookup is exactly the "unknowingly supersede something" risk
          // this whole panel exists to prevent.
          const targetUnresolved = !!d.target_fact_id && target?.status !== "loaded";
          return (
            <li key={d.id} className="diff-card">
              <p className="diff-meta">
                <span className="proposer">from {d.subject}</span>
              </p>
              {d.target_fact_id && (
                <div className="target-fact">
                  <p className="target-fact-label">This replaces an existing fact:</p>
                  {target?.status === "loading" && <p>Loading target fact…</p>}
                  {target?.status === "error" && (
                    <p className="error">Could not load target fact: {target.message}</p>
                  )}
                  {target?.status === "loaded" && (
                    <p className="diff-content old-content">{target.fact.content}</p>
                  )}
                </div>
              )}
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
                <button disabled={busyId === d.id || targetUnresolved} onClick={() => decide(d.id, "approve")}>
                  Approve
                </button>
                <button disabled={busyId === d.id} onClick={() => decide(d.id, "reject")} className="secondary">
                  Reject
                </button>
              </div>
            </li>
          );
        })}
      </ul>
    </section>
  );
}
