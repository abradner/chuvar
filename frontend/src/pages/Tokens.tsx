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

export interface TokensPageProps {
  // Lets the shell block navigation while an unrecoverable credential is on
  // screen. This page's state dies with the component, and App unmounts it on
  // every tab change — see the reveal-retention comment below.
  onRevealChange?: (pending: boolean) => void;
}

export function TokensPage({ onRevealChange }: TokensPageProps = {}) {
  const [tokens, setTokens] = useState<ReviewerToken[]>([]);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);
  const [newLabel, setNewLabel] = useState("");
  // Shown once, immediately after creation, and never re-fetchable — the server
  // kept only a hash (see CreatedReviewerToken). Losing it before the operator
  // copies it is the worst outcome this page can produce: on a *first* device,
  // the enrollment gate has already latched (the ever-enrolled count includes
  // revoked rows), so the next create demands a code no surviving credential
  // can generate, and recovery is direct DB surgery. Every path that can clear
  // this state is therefore guarded — see dismiss, the beforeunload effect, and
  // onRevealChange.
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

  // Reload/close is the one destroyer the page cannot intercept itself, so hand
  // it to the browser. Registered only while a reveal is pending, so ordinary
  // navigation is never nagged.
  useEffect(() => {
    if (!justCreated) return;
    const warn = (e: BeforeUnloadEvent) => e.preventDefault();
    window.addEventListener("beforeunload", warn);
    return () => window.removeEventListener("beforeunload", warn);
  }, [justCreated]);

  // Tab switches unmount this component outright, taking justCreated with it,
  // so the shell has to do the blocking. Reported rather than handled here
  // because the nav lives in App.
  useEffect(() => {
    onRevealChange?.(justCreated !== null);
  }, [justCreated, onRevealChange]);

  const createToken = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);

    const label = newLabel.trim();
    if (!label) {
      setError("Label is required");
      return;
    }

    // TOTP is only required once a device has ever been enrolled (backend's
    // createToken doc comment), and this page can't know that in advance — so
    // unlike Grants.tsx's mandatory prompts, an empty code is a legitimate
    // answer here (a genuinely fresh install).
    //
    // Cancel and empty are therefore NOT equivalent, and prompt() distinguishes
    // them: null means cancelled, "" means submitted-blank. Cancel aborts;
    // blank proceeds with no code and lets the server decide whether one was
    // required. Collapsing the two would make cancelling a create still create.
    //
    // The wording says "never enrolled", not "first device": the backend counts
    // ever-enrolled *including revoked* rows, so an operator who has revoked
    // every device would otherwise read "first device" as true, leave it blank,
    // and get a bare 401 they cannot act on.
    // Trimmed for the same paste-adds-whitespace reason as Grants.tsx.
    const totpInput = window.prompt(
      "Enter a TOTP code from an already-enrolled device (leave blank only on a new install that has never enrolled one)",
    );
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

  const dismiss = () => {
    if (!window.confirm("Dismiss? The bearer token and TOTP setup key above cannot be shown again.")) return;
    setJustCreated(null);
  };

  // Revoking is not reversible and the API exposes no "this token is the one
  // you are authenticated with" marker, so the UI genuinely cannot warn
  // precisely — it can only make sure the click was deliberate. Revoking the
  // browser's own token (VITE_API_AUTH_TOKEN) locks this UI out, and because
  // the enrollment gate counts revoked rows, minting a replacement then needs a
  // code from the device just revoked. Recovery is DB surgery.
  const revoke = async (id: string, label: string) => {
    if (
      !window.confirm(
        `Revoke "${label}"? This cannot be undone. If it is the token this browser is using, you will be locked out and recovery requires direct database access.`,
      )
    ) {
      return;
    }
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
            <button onClick={dismiss}>Dismiss</button>
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
                <button disabled={busyId === t.id} onClick={() => revoke(t.id, t.label)} className="secondary">
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
        {tokens.length === 0 && <li className="empty">No reviewer tokens yet.</li>}
      </ul>

      <form onSubmit={createToken} className="new-grant-form">
        <h3>New device</h3>
        <label>
          Label
          <input value={newLabel} onChange={(e) => setNewLabel(e.target.value)} placeholder="alex-laptop" />
        </label>
        {/* Disabling this while a reveal is pending is the *single* guard
            against a second create overwriting an uncopied credential.
            An earlier revision also re-checked justCreated inside the submit
            handler, justified as "a form still submits on Enter" — that is
            false (HTML implicit submission does not fire when the only submit
            button is disabled), so the branch was unreachable and its comment
            was an aspirational claim of a layer that did not exist. Removed:
            it failed the deletion test (CLAUDE.md principle 7 — enforcement
            exists exactly once). Found by independent review. */}
        <button type="submit" disabled={creating || justCreated !== null}>
          Create token
        </button>
      </form>
    </section>
  );
}
