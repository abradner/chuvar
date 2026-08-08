// The dumb view of the Tokens feature: props in, JSX out. It imports nothing
// from api/ and holds no state beyond the label input it owns — every rule
// about *when* things may happen lives in useTokens (AGENTS.md §6, "UI
// component standard"). The payoff is in TokensView.test.tsx: rendering this
// with plain props needs no API mocks and no async.
import { type FormEvent, useState } from "react";
import type { CreatedReviewerToken, ReviewerToken } from "./useTokens";
import { enrollmentSecret } from "./enrollmentSecret";

export interface TokensViewProps {
  tokens: ReviewerToken[];
  loading: boolean;
  loadError: string | null;
  error: string | null;
  busyId: string | null;
  creating: boolean;
  justCreated: CreatedReviewerToken | null;
  // create returns whether it succeeded so the view knows to clear its label
  // field — the one piece of state the view owns.
  onCreate: (label: string) => Promise<boolean>;
  onDismissReveal: () => void;
  onRevoke: (id: string, label: string) => void;
}

export function TokensView({
  tokens,
  loading,
  loadError,
  error,
  busyId,
  creating,
  justCreated,
  onCreate,
  onDismissReveal,
  onRevoke,
}: TokensViewProps) {
  const [newLabel, setNewLabel] = useState("");

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (await onCreate(newLabel)) setNewLabel("");
  };

  return (
    <section>
      <h2>Reviewer tokens</h2>
      {loadError && <p className="error">{loadError}</p>}
      {error && <p className="error">{error}</p>}

      {justCreated && (
        <div className="grant-card token-reveal">
          <p>
            <strong>{justCreated.label}</strong> created. Copy both now — neither is shown again, and a lost setup key
            on a first device can only be recovered from the database.
          </p>
          <label>
            Bearer token
            {/* autoComplete/spellCheck off: these hold a live credential, and
                neither a password manager's save prompt nor a spellchecker
                should ever see it. Both inputs sit outside the <form>, so
                form-submit capture does not apply. */}
            <input
              readOnly
              autoComplete="off"
              spellCheck={false}
              value={justCreated.token}
              onFocus={(e) => e.currentTarget.select()}
            />
          </label>
          <label>
            TOTP setup key
            {/* Shown as a plain setup key rather than a QR code so this page
                adds no new dependency for a one-time, low-frequency operator
                action — see enrollmentSecret above. */}
            <input
              readOnly
              autoComplete="off"
              spellCheck={false}
              value={enrollmentSecret(justCreated.totp_enroll_uri)}
              onFocus={(e) => e.currentTarget.select()}
            />
          </label>
          <div className="actions">
            <button onClick={onDismissReveal}>Dismiss</button>
          </div>
        </div>
      )}

      {loading && <p>Loading tokens…</p>}
      <ul className="grant-list">
        {tokens.map((t) => (
          <li key={t.id} className="grant-card">
            <p className="scopes">{t.label}</p>
            <p className="grant-meta">
              {t.active ? "active" : "revoked"}
              {t.last_used_at && ` · last used ${new Date(t.last_used_at).toLocaleString()}`}
            </p>
            {t.active && (
              <div className="actions">
                <button disabled={busyId === t.id} onClick={() => onRevoke(t.id, t.label)} className="secondary">
                  Revoke
                </button>
              </div>
            )}
          </li>
        ))}
        {/* Wrapped in <li> because a <ul> may only contain <li> children —
            bare <p> here is invalid HTML and reads poorly to a screen reader.
            The sibling Grants/StagedDiffs pages still have the unwrapped
            shape; not fixed here to keep this PR to its own surface. */}
        {/* Gated on !loading && !loadError: tokens starts as [] regardless of
            whether the first fetch has even returned yet, so without these
            an in-flight request or a failed one both rendered as a confirmed
            empty inventory — including alongside the error message above.
            Found in review (Copilot). */}
        {!loading && !loadError && tokens.length === 0 && <li className="empty">No reviewer tokens yet.</li>}
      </ul>

      <form onSubmit={submit} className="new-grant-form">
        <h3>New device</h3>
        <label>
          Label
          <input value={newLabel} onChange={(e) => setNewLabel(e.target.value)} placeholder="alex-laptop" />
        </label>
        {/* UX only, not the enforcement: this stops an impatient click, but the
            actual guard against a second create overwriting an uncopied
            credential lives in useTokens.create, so any other caller of the
            hook is covered too (AGENTS.md §6). An earlier revision put a
            duplicate check in this file's own submit handler instead; it was
            unreachable — HTML implicit submission does not fire while the
            sole submit button is disabled — and failed the deletion test, so
            it was removed rather than kept as a second, dead copy (see the
            PR #56 review record). */}
        <button type="submit" disabled={creating || justCreated !== null}>
          Create token
        </button>
      </form>
    </section>
  );
}
