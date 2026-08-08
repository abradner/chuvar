// The data side of the Tokens feature — fetching, state, domain rules, and the
// guard ceremonies around destructive actions. No JSX: everything UI-shaped
// lives in TokensView, everything data-shaped lives here (AGENTS.md §6, "UI
// component standard"). The guard ceremonies (confirm before revoke/dismiss)
// are deliberately here rather than in the view, so any future view over the
// same data inherits them instead of re-implementing them — they are
// politeness, not enforcement (the server's auth/TOTP gates are the
// enforcement, per CLAUDE.md's deletion test), but politeness that should not
// quietly vanish in a redesign.
import { useCallback, useEffect, useState } from "react";
import { api, ApiError, type CreatedReviewerToken, type ReviewerToken } from "../../api/client";

export interface UseTokensOptions {
  // Lets the shell block navigation while an unrecoverable credential is on
  // screen. The page's state dies with the component, and App unmounts pages
  // on every tab change — see justCreated below.
  onRevealChange?: (pending: boolean) => void;
}

export function useTokens({ onRevealChange }: UseTokensOptions = {}) {
  const [tokens, setTokens] = useState<ReviewerToken[]>([]);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);
  // Shown once, immediately after creation, and never re-fetchable — the server
  // kept only a hash (see CreatedReviewerToken). Losing it before the operator
  // copies it is the worst outcome this feature can produce: on a *first*
  // device, the enrollment gate has already latched (the ever-enrolled count
  // includes revoked rows), so the next create demands a code no surviving
  // credential can generate, and recovery is direct DB surgery. Every path
  // that can clear this state is guarded — dismiss confirms, the beforeunload
  // effect covers reload/close, and onRevealChange lets the shell block tab
  // switches.
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

  // Tab switches unmount the page outright, taking justCreated with it, so the
  // shell has to do the blocking. Reported rather than handled here because
  // the nav lives in App.
  useEffect(() => {
    onRevealChange?.(justCreated !== null);
  }, [justCreated, onRevealChange]);

  const create = useCallback(async (label: string) => {
    setError(null);

    const trimmed = label.trim();
    if (!trimmed) {
      setError("Label is required");
      return false;
    }

    // TOTP is only required once a device has ever been enrolled (backend's
    // createToken doc comment), and this page can't know that in advance — so
    // unlike the Grants page's mandatory prompts, an empty code is a
    // legitimate answer here (a genuinely fresh install).
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
    // Trimmed for the paste-adds-whitespace reason as the Grants page.
    const totpInput = window.prompt(
      "Enter a TOTP code from an already-enrolled device (leave blank only on a new install that has never enrolled one)",
    );
    if (totpInput === null) return false;
    const totpCode = totpInput.trim();

    setCreating(true);
    try {
      const created = await api.createToken(trimmed, totpCode || undefined);
      setJustCreated(created);
      setRefreshKey((k) => k + 1);
      return true;
    } catch (e) {
      setError(e instanceof ApiError ? e.message : String(e));
      return false;
    } finally {
      setCreating(false);
    }
  }, []);

  const dismissReveal = useCallback(() => {
    if (!window.confirm("Dismiss? The bearer token and TOTP setup key above cannot be shown again.")) return;
    setJustCreated(null);
  }, []);

  // Revoking is not reversible and the API exposes no "this token is the one
  // you are authenticated with" marker, so the UI genuinely cannot warn
  // precisely — it can only make sure the click was deliberate. Revoking the
  // browser's own token (VITE_API_AUTH_TOKEN) locks this UI out, and because
  // the enrollment gate counts revoked rows, minting a replacement then needs
  // a code from the device just revoked. Recovery is DB surgery.
  const revoke = useCallback(async (id: string, label: string) => {
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
  }, []);

  return { tokens, loadError, error, busyId, creating, justCreated, create, dismissReveal, revoke };
}
