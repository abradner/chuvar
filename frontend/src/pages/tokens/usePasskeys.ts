// The data side of the Passkeys (WebAuthn) feature — fetching, state, and the
// two real browser ceremonies (navigator.credentials.create()/.get()), kept
// out of PasskeysView per AGENTS.md §6, "UI component standard": no JSX here,
// everything UI-shaped lives in the view. Directly against
// navigator.credentials rather than a WebAuthn helper library — see
// webauthnCodec.ts's own doc comment for why that's a small, fixed
// conversion, not a dependency-shaped problem.
import { useCallback, useEffect, useState } from "react";
import { api, ApiError, type SecondFactor, type WebAuthnCredential } from "../../api/client";
import {
  decodeCreationOptions,
  decodeRequestOptions,
  encodeAssertionHeader,
  encodeCreationResponse,
} from "./webauthnCodec";

export type { WebAuthnCredential };

// browserSupportsPasskeys is read once per hook instance, not per render —
// support doesn't change mid-session, and re-checking it on every render
// would be pointless work for a value that's already been true or false
// since the page loaded.
function browserSupportsPasskeys(): boolean {
  return typeof window !== "undefined" && "PublicKeyCredential" in window && typeof navigator?.credentials?.create === "function";
}

// describeCeremonyError turns the two ceremony-specific failure shapes
// (a user-cancelled/timed-out prompt, and everything else) into a message an
// operator can act on, rather than a raw DOMException name or ApiError JSON
// blob — the "legibility" half of this ticket's operator-experience brief.
function describeCeremonyError(e: unknown): string {
  if (e instanceof DOMException && (e.name === "NotAllowedError" || e.name === "AbortError")) {
    return "Passkey ceremony was cancelled or timed out — try again.";
  }
  if (e instanceof ApiError) return e.message;
  if (e instanceof Error) return e.message;
  return String(e);
}

export function usePasskeys() {
  const [credentials, setCredentials] = useState<WebAuthnCredential[]>([]);
  // Same "confirmed empty vs. haven't heard back yet vs. failed" distinction
  // as useTokens' loading flag — see that hook's own comment on why this
  // can't just be derived from credentials.length.
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [registering, setRegistering] = useState(false);
  const [refreshKey, setRefreshKey] = useState(0);
  const [supported] = useState(browserSupportsPasskeys);

  useEffect(() => {
    if (!supported) {
      // Nothing to fetch in a browser that can't do WebAuthn at all — leaves
      // loading=true forever otherwise, which PasskeysView would render as a
      // perpetual spinner instead of the "not supported" message.
      setLoading(false);
      return;
    }
    const controller = new AbortController();
    api
      .listWebAuthnCredentials(controller.signal)
      .then((c) => {
        setCredentials(c);
        setLoadError(null);
        setLoading(false);
      })
      .catch((e: unknown) => {
        if (e instanceof DOMException && e.name === "AbortError") return;
        setLoadError(e instanceof ApiError ? e.message : String(e));
        setLoading(false);
      });
    return () => controller.abort();
  }, [supported, refreshKey]);

  const register = useCallback(
    async (label: string) => {
      // Same chokepoint reasoning as useTokens.create: this is the actual
      // guard against a double-submit, not just the view's disabled button
      // (AGENTS.md §6 — guard ceremonies live in the hook so any future
      // caller inherits them).
      if (registering) {
        setError("A registration is already in flight.");
        return false;
      }
      if (!supported) {
        setError("This browser does not support passkeys (WebAuthn).");
        return false;
      }
      setError(null);

      const trimmed = label.trim();
      if (!trimmed) {
        setError("Label is required");
        return false;
      }

      setRegistering(true);
      try {
        // The server always demands a factor this device token has already
        // enrolled (requireExistingSecondFactor — there is deliberately no
        // factorless path). Which factor is known client-side: if a live
        // passkey exists, prove it via a real assertion ceremony (no typing);
        // otherwise this is the device's first passkey and the TOTP secret
        // enrolled when the token was minted is the only factor it can have.
        let factor: SecondFactor;
        if (credentials.some((c) => c.active)) {
          const assertionOptions = await api.webauthnAssertBegin();
          const assertionCred = (await navigator.credentials.get(
            decodeRequestOptions(assertionOptions),
          )) as PublicKeyCredential | null;
          if (!assertionCred) {
            setError("The browser did not return an assertion.");
            return false;
          }
          factor = { webauthnAssertion: encodeAssertionHeader(assertionCred) };
        } else {
          // Cancel (null) aborts quietly, like every prompt-cancel path;
          // blank is a real refusal the operator should see, since the
          // server would only bounce it with the same message less directly.
          const totpInput = window.prompt("Enter this device's TOTP code to authorize adding a passkey.");
          if (totpInput === null) return false;
          const totpCode = totpInput.trim();
          if (!totpCode) {
            setError("A TOTP code is required to enroll this device's first passkey.");
            return false;
          }
          factor = { totpCode };
        }

        const creationOptions = await api.webauthnRegisterBegin(factor);

        const cred = (await navigator.credentials.create(decodeCreationOptions(creationOptions))) as PublicKeyCredential | null;
        if (!cred) {
          setError("The browser did not return a credential.");
          return false;
        }

        const created = await api.webauthnRegisterFinish(encodeCreationResponse(cred, trimmed));
        setCredentials((prev) => [...prev, created]);
        return true;
      } catch (e) {
        setError(describeCeremonyError(e));
        return false;
      } finally {
        setRegistering(false);
      }
    },
    [registering, supported, credentials],
  );

  const revoke = useCallback(async (id: string, label: string) => {
    if (!window.confirm(`Revoke passkey "${label}"? This cannot be undone.`)) return;
    setBusyId(id);
    setError(null);
    try {
      await api.revokeWebAuthnCredential(id);
      setCredentials((prev) => prev.map((c) => (c.id === id ? { ...c, active: false } : c)));
      setRefreshKey((k) => k + 1);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : String(e));
    } finally {
      setBusyId(null);
    }
  }, []);

  return { credentials, loading, loadError, error, busyId, registering, supported, register, revoke };
}
