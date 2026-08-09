// The dumb view of the Passkeys feature: props in, JSX out. Imports nothing
// from api/ and holds no state beyond the label input it owns — every rule
// about *when* things may happen lives in usePasskeys (AGENTS.md §6, "UI
// component standard"). Reuses the existing .grant-card/.grant-list/
// .new-grant-form classes from the tokens/grants pages rather than inventing
// a parallel style — this is the same "operator inventory with actions"
// shape as those lists.
import { type FormEvent, useState } from "react";
import type { WebAuthnCredential } from "./usePasskeys";

export interface PasskeysViewProps {
  credentials: WebAuthnCredential[];
  loading: boolean;
  loadError: string | null;
  error: string | null;
  busyId: string | null;
  registering: boolean;
  supported: boolean;
  // onRegister returns whether it succeeded so the view knows to clear its
  // label field — the one piece of state the view owns.
  onRegister: (label: string) => Promise<boolean>;
  onRevoke: (id: string, label: string) => void;
}

export function PasskeysView({
  credentials,
  loading,
  loadError,
  error,
  busyId,
  registering,
  supported,
  onRegister,
  onRevoke,
}: PasskeysViewProps) {
  const [newLabel, setNewLabel] = useState("");

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (await onRegister(newLabel)) setNewLabel("");
  };

  return (
    <section>
      <h2>Passkeys</h2>
      <p className="grant-meta">
        An additional factor alongside TOTP — either satisfies the same server-side check. Adding a passkey once any
        factor is already enrolled requires proving that existing factor first.
      </p>
      {!supported && <p className="error">This browser does not support passkeys (WebAuthn).</p>}
      {loadError && <p className="error">{loadError}</p>}
      {error && <p className="error">{error}</p>}

      {loading && <p>Loading passkeys…</p>}
      <ul className="grant-list">
        {credentials.map((c) => (
          <li key={c.id} className="grant-card">
            <p className="scopes">{c.label}</p>
            <p className="grant-meta">
              {c.active ? "active" : "revoked"}
              {c.last_used_at && ` · last used ${new Date(c.last_used_at).toLocaleString()}`}
              {c.clone_warning_at &&
                ` · POSSIBLE CLONE DETECTED ${new Date(c.clone_warning_at).toLocaleString()} — revoked automatically`}
            </p>
            {c.active && (
              <div className="actions">
                <button disabled={busyId === c.id} onClick={() => onRevoke(c.id, c.label)} className="secondary">
                  Revoke
                </button>
              </div>
            )}
          </li>
        ))}
        {!loading && !loadError && supported && credentials.length === 0 && <li className="empty">No passkeys enrolled yet.</li>}
      </ul>

      {supported && (
        <form onSubmit={submit} className="new-grant-form">
          <h3>New passkey</h3>
          <label>
            Label
            <input value={newLabel} onChange={(e) => setNewLabel(e.target.value)} placeholder="yubikey-5c" />
          </label>
          {/* UX only, not the enforcement — see TokensView's identical comment
              on the equivalent button; the real guard is registering's check
              in usePasskeys.register, which covers any future caller of the
              hook too. */}
          <button type="submit" disabled={registering}>
            {registering ? "Waiting for authenticator…" : "Add passkey"}
          </button>
        </form>
      )}
    </section>
  );
}
