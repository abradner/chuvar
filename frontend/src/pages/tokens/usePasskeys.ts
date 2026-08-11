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
  // Both create() and get() are checked, not just create(): this hook drives
  // both ceremonies (registration uses create, assertion uses get), so a
  // browser exposing only one would pass a create-only check and then throw at
  // runtime the first time an assertion is attempted — reporting "supported"
  // and then failing is worse than reporting "not supported" up front. Found in
  // review.
  return (
    typeof window !== "undefined" &&
    "PublicKeyCredential" in window &&
    typeof navigator?.credentials?.create === "function" &&
    typeof navigator?.credentials?.get === "function"
  );
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

// promptForTotpFactor is the shared "ask for a TOTP code" ceremony both
// register() branches below use — one when this is the device's first
// passkey (no assertion possible yet), the other as the fallback when an
// existing passkey couldn't be asserted. null means abort register()
// entirely: either the operator cancelled the prompt (same quiet-abort
// stance as every other prompt-cancel path in this hook) or typed a blank
// code, in which case setError is called first so the refusal is visible —
// the server would only bounce a blank/missing code with the same message
// less directly.
function promptForTotpFactor(
  promptMessage: string,
  blankErrorMessage: string,
  setError: (e: string | null) => void,
): SecondFactor | null {
  const totpInput = window.prompt(promptMessage);
  if (totpInput === null) return null;
  const totpCode = totpInput.trim();
  if (!totpCode) {
    setError(blankErrorMessage);
    return null;
  }
  return { totpCode };
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
        // factorless path), and accepts EITHER a TOTP code or a WebAuthn
        // assertion whenever both are enrolled: the assertion header only
        // wins when it's actually present on the request (see that
        // handler's doc comment), it isn't mandatory just because a passkey
        // exists. If a live passkey exists, prefer proving it via a real
        // assertion ceremony (no typing) — but when that can't be produced
        // (cancelled, timed out, the authenticator isn't to hand, or any
        // other ceremony failure), fall back to the same TOTP prompt the
        // device's first-passkey path uses below, rather than dead-ending
        // the operator into "revoke your only passkey before you can enroll
        // a replacement." Every legitimately-minted reviewer token has a
        // TOTP secret from createToken (see its doc comment), so this
        // fallback is always available in practice. Found in review: the
        // previous version demanded an assertion unconditionally whenever
        // any active passkey existed, which is strictly more restrictive
        // than what the server itself accepts.
        let factor: SecondFactor | null = null;
        if (credentials.some((c) => c.active)) {
          try {
            const assertionOptions = await api.webauthnAssertBegin();
            const assertionCred = (await navigator.credentials.get(
              decodeRequestOptions(assertionOptions),
            )) as PublicKeyCredential | null;
            if (!assertionCred) {
              throw new Error("The browser did not return an assertion.");
            }
            factor = { webauthnAssertion: encodeAssertionHeader(assertionCred) };
          } catch {
            factor = promptForTotpFactor(
              "Could not use an existing passkey to authorize this (cancelled, unavailable, or the authenticator " +
                "isn't to hand). Enter this device's TOTP code to authorize adding a passkey instead.",
              "A TOTP code is required to enroll a passkey when no existing passkey is available to prove.",
              setError,
            );
          }
        } else {
          factor = promptForTotpFactor(
            "Enter this device's TOTP code to authorize adding a passkey.",
            "A TOTP code is required to enroll this device's first passkey.",
            setError,
          );
        }
        if (factor === null) return false;

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
