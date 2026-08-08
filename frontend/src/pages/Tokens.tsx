import { type FormEvent, useEffect, useState } from "react";
import { api, ApiError, type CreatedReviewerToken, type ReviewerToken } from "../api/client";

// enrollmentSecret pulls the base32 secret out of an otpauth:// URI — the form
// most authenticator apps accept under "enter a setup key manually". Falls back
// to the whole URI rather than throwing: this runs during render, where an
// unhandled parse error would blank the page instead of degrading, and the
// operator can still enrol from the raw URI. The value is unrecoverable after
// this one render (see CreatedReviewerToken), so failing soft matters more here
// than anywhere else in the app.
function enrollmentSecret(uri: string): string {
  try {
    // `||`, not `??`: searchParams.get returns "" (not null) for a valueless
    // `?secret=`, and an empty setup key field is the one outcome worse than
    // showing the raw URI — the operator would have nothing to enrol from and
    // no way to get it back. Found in review.
    return new URL(uri).searchParams.get("secret") || uri;
  } catch {
    return uri;
  }
}

export function TokensPage() {
  const [tokens, setTokens] = useState<ReviewerToken[]>([]);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);
  const [newLabel, setNewLabel] = useState("");
  // Shown once, immediately after creation — never re-fetchable (see
  // CreatedReviewerToken's doc comment) — so this page is the only place it's
  // ever displayed, and clearing it (dismiss button, or creating another
  // token) is a one-way trip.
  const [justCreated, setJustCreated] = useState<CreatedReviewerToken | null>(null);
  const [refreshKey, setRefreshKey] = useState(0);

  useEffect(() => {
    const controller = new AbortController();
    api
      .listTokens(controller.signal)
      .then((t) => {
        setTokens(t);
        setLoadError(null);
      })
      .catch((e: unknown) => {
        if (e instanceof DOMException && e.name === "AbortError") return;
        setLoadError(e instanceof ApiError ? e.message : String(e));
      });
    return () => controller.abort();
  }, [refreshKey]);

  const createToken = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);

    // Creating again while a reveal is still on screen would overwrite
    // justCreated and destroy a credential that cannot be recovered from
    // anywhere — the server only ever kept its hash. Dismissing is an explicit
    // "I've copied it", so require that first. Checked here as well as via the
    // disabled button because a form still submits on Enter.
    if (justCreated) {
      setError("Copy and dismiss the token above before creating another — it cannot be shown again.");
      return;
    }

    const label = newLabel.trim();
    if (!label) {
      setError("Label is required");
      return;
    }

    // TOTP is only required once a device has ever been enrolled (backend's
    // createToken doc comment), and this page can't know that in advance — so
    // unlike Grants.tsx's mandatory prompts, an empty code is a legitimate
    // answer here (the first-ever, bootstrap enrollment).
    //
    // Cancel and empty are therefore NOT equivalent, and prompt() distinguishes
    // them: null means cancelled, "" means submitted-blank. Cancel aborts;
    // blank proceeds with no code and lets the server decide whether one was
    // required. Collapsing the two would make cancelling a create still create.
    // Trimmed for the same paste-adds-whitespace reason as Grants.tsx.
    const totpInput = window.prompt("Enter TOTP code from an already-enrolled device (leave blank if this is the first device)");
    if (totpInput === null) return;
    const totpCode = totpInput.trim();

    setCreating(true);
    try {
      const created = await api.createToken(label, totpCode || undefined);
      setJustCreated(created);
      setNewLabel("");
      setRefreshKey((k) => k + 1);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : String(e));
    } finally {
      setCreating(false);
    }
  };

  const revoke = async (id: string) => {
    setBusyId(id);
    setError(null);
    try {
      await api.revokeToken(id);
      setRefreshKey((k) => k + 1);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : String(e));
    } finally {
      setBusyId(null);
    }
  };

  return (
    <section>
      <h2>Reviewer tokens</h2>
      {loadError && <p className="error">{loadError}</p>}
      {error && <p className="error">{error}</p>}

      {justCreated && (
        <div className="grant-card token-reveal">
          <p>
            <strong>{justCreated.label}</strong> created. Copy these now — neither is shown again.
          </p>
          <label>
            Bearer token
            <input readOnly value={justCreated.token} onFocus={(e) => e.currentTarget.select()} />
          </label>
          <label>
            TOTP setup key
            {/* Shown as a plain setup key rather than a QR code so this page
                adds no new dependency for a one-time, low-frequency operator
                action — see enrollmentSecret above. */}
            <input
              readOnly
              value={enrollmentSecret(justCreated.totp_enroll_uri)}
              onFocus={(e) => e.currentTarget.select()}
            />
          </label>
          <div className="actions">
            <button onClick={() => setJustCreated(null)}>Dismiss</button>
          </div>
        </div>
      )}

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
                <button disabled={busyId === t.id} onClick={() => revoke(t.id)} className="secondary">
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
        {tokens.length === 0 && (
          <li className="empty">No reviewer tokens yet.</li>
        )}
      </ul>

      <form onSubmit={createToken} className="new-grant-form">
        <h3>New device</h3>
        <label>
          Label
          <input value={newLabel} onChange={(e) => setNewLabel(e.target.value)} placeholder="alex-laptop" />
        </label>
        <button type="submit" disabled={creating || justCreated !== null}>
          Create token
        </button>
      </form>
    </section>
  );
}
